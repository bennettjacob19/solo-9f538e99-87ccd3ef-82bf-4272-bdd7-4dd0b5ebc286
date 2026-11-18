# DNS 值班解析系统（serve-stale 演练）

平台值班场景：内部服务的权威 DNS 失联时，解析器继续为已确认的地址提供解析，
但记录被删除（NXDOMAIN）后绝不把旧地址交给调用方。

## 组成

| 服务 | 模块 | 端口 | 说明 |
|---|---|---|---|
| `auth` | `app.auth_server` | UDP 5354 | 本地权威端，行为可由网页实时切换 |
| `resolver` | `app.resolver` | UDP 5353 | 缓存/serve-stale UDP 解析器 |
| `web` | `app.web` | HTTP 8000 | FastAPI 操作网页 |

三者通过共享卷上的 SQLite（WAL 模式）协作：`control` 表存权威端行为，
`cache` 表存解析器缓存（**绝对时间戳**），`query_log`/`auth_log` 表供网页展示。

## 运行

```bash
docker compose up --build
# 网页:  http://localhost:8000
# 查询:  dig @127.0.0.1 -p 5353 service.example A
```

无 Docker 的本地运行（等价三进程）：

```bash
pip install -r requirements.txt
DB_PATH=/tmp/dns/app.db AUTH_PORT=15354 python -m app.auth_server &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 AUTH_PORT=15354 python -m app.resolver &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 WEB_PORT=8000 python -m app.web &
```

自测（自动拉起三进程，跑全部关键交错，约 130 秒）：

```bash
python tests/selftest.py
```

## 语义（默认值，可用环境变量调整）

- 成功答复 TTL = **5 秒**（`FRESH_TTL`），缓存命中时 TTL 倒数。
- 过期后重新回源；上游超时（`UPSTREAM_TIMEOUT`=2s）时旧 A 最多沿用 **20 秒**
  （`STALE_WINDOW`），应答 TTL 为剩余可用时长；超过即 **SERVFAIL**。
- **NXDOMAIN 只作 5 秒新鲜缓存，绝不作过期备用**：过期+上游超时 → SERVFAIL。
- 解析器确认 NXDOMAIN 时**立即持久清除旧 A**：此后任何答复都不再含旧 A。
- 每次回源用**独立 socket + 随机事务 ID + 问题匹配**，超时后迟到的旧答复
  无人接收、也不会被错配给后续查询，因此无法复活旧记录。
- 缓存期限以绝对 epoch 存于 SQLite，**重启不延长旧 A 的有效期**
  （窗口继续倒数，不会重新计时）。

网页可切换权威端行为：`a`（可改 IP）/ `nxdomain` / `delay`（延迟应答，默认 3s，
大于上游超时，用于演练迟到应答）/ `timeout`（不应答，模拟权威端失联）。
网页"发起查询"经解析器发真实 DNS 查询，展示实际答复（rcode、应答、TTL）
与来源（`upstream` / `cache-fresh` / `cache-stale` / `none`，由解析器在
additional 段 TXT `_src.<域名>` 中带回），并展示双方日志。

固定域名默认 `service.example`（`FIXED_DOMAIN` 可改）。解析器只服务该域名，
其余名称 REFUSED，非 A/AAAA 查询返回 NODATA。

## DNS64

仅 IPv6 的客户端经 NAT64 访问只有 A 记录的 `service.example`：解析器的 AAAA
查询不向上游发 AAAA，而是复用 A 的缓存/回源/serve-stale 路径，把 IPv4 地址
嵌入已提交的 **/96** 合成前缀（默认 `64:ff9b::/96`，`DNS64_PREFIX` 可改，
网页可随时修改并立即生效）。

- 网页"DNS64 合成前缀"可设置 /96 前缀；非法前缀（非 IPv6、非 /96）或写入
  失败时返回错误，**原前缀继续有效**。
- 前缀持久化在 `dns64` 表，已提交的前缀**重启后仍然有效**；只有成功的更新
  才会替换它。
- 合成答复的 TTL **不超过所用 A 的剩余有效时间**：新鲜 A 用剩余 fresh 时间，
  过期后仅在原 20 秒窗口内用剩余 stale 时间；窗口结束即不再合成。
- 新鲜 NXDOMAIN 原样返回（rcode=NXDOMAIN）；过期且回源失败、没有可用 A 时
  返回 SERVFAIL。
- 解析器在**跨进程锁**内读取前缀并发送 AAAA 报文；网页在同一把锁内提交新
  前缀。因此前缀更新成功后发出的任何 AAAA 都不含旧前缀（即使查询在更新前
  已开始）。
- A 查询保持原有规则不变。
- 网页"查询 AAAA（DNS64）"发起真实 AAAA 查询并显示答复、TTL 与来源。

## 文件

```
app/common.py       配置 + SQLite 状态面（含 DNS64 前缀）
app/auth_server.py  可控权威端（dnslib 编解码，线程并发）
app/resolver.py     缓存/serve-stale 解析器 + DNS64 AAAA 合成
app/web.py          FastAPI 操作网页
tests/selftest.py   端到端自测（A–G 七组场景，含 DNS64）
Dockerfile / docker-compose.yml / requirements.txt
```
