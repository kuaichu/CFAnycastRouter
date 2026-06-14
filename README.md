# CF Anycast Router

`CF Anycast Router` 是一个本地 Anycast 行为学习器。你给它少量 Cloudflare 种子 IP 或 CIDR 段，它从本机真实网络探测这些入口属于哪个 Cloudflare POP，逐步学习哪些 `/24` 对当前运营商更容易出 HK / JP / SG，然后从热池里挑当前最优入口。

它不是全网爆破器，也不是公共测速工具。核心是：局部聚类学习。

## 三层池子

### 1. Seed Pool

手动维护，几十个就够：

```yaml
seed_ips:
  - "104.20.23.137"
  - "104.26.0.1"

seed_cidrs:
  - "104.20.0.0/16"
  - "172.67.0.0/16"
```

如果给的是 `/16`，程序不会扫完整段，而是按 `seed_cidr_step` 抽 `/24`；每个 `/24` 再按 `sample_step` 抽样：

```text
104.20.23.1
104.20.23.5
104.20.23.9
104.20.23.13
...
```

### 2. Learned Pool

当某个 `/24` 的样本大部分命中首选 POP，比如 `HK / JP / SG`，这个段会被提升为 Learned：

```text
104.20.23.0/24  cu  preferred=100%  samples=9  learned
```

以后会优先继续扫描这个段，而不是平均撒网。

### 3. Hot Pool

某个 IP 同时满足：

- POP 属于 `preferred_pops`
- score 低于 `hot_max_score`
- 丢包和尖刺不过线

就进入 Hot Pool。真正切换时优先从 Hot / Learned 里选。

## 评分

```text
base_score =
avg_rtt
+ jitter * 0.5
+ loss_rate * 500
+ spike_rate * 80
+ pop_penalty
+ drift_penalty
+ hijack_penalty
- learned_bonus
```

`loss_rate` 和 `spike_rate` 是 0-1 小数。`HK / JP / SG` 不加 POP 惩罚，`US +100`，`EU +150`，`unknown` 且 RTT 大于 100ms 时 `+80`。

如果启用了 `speed_test`，程序会先按基础分筛出前 `top_n` 个候选，再对这些 IP 直连 Cloudflare 官方测速源：

```text
https://speed.cloudflare.com/__down?bytes=N
```

测速请求会连接候选 IP 的 443 端口，但 SNI/Host 使用 `speed.cloudflare.com`。完成测速的短名单候选会用下载耗时、抖动和失败率重新排序；其余候选只作为兜底。

## 漂移检测

状态文件会记录每个 IP 和 `/24` 的历史：

- IP 在当前运营商下的 POP 时间线
- `/24` 的 POP 命中次数
- `/24` 的首选 POP 概率
- 时段画像：`00:00-06:00`、`06:00-12:00`、`12:00-18:00`、`18:00-24:00`
- Hot IP 列表

状态默认在：

```text
data/state.json
```

## 命令

```powershell
go run . discover config.yaml
go run . probe config.yaml
go run . once config.yaml
go run . run config.yaml
go run . server config.yaml
go run . agent agent.yaml
```

| 命令 | 作用 |
|---|---|
| `discover` | 展示本轮会扫描的 Seed / Learned / Hot 目标 |
| `probe` / `trace` / `score` | 只探测和学习，不切换输出 |
| `once` / `switch` | 探测、学习、评分，满足滞后条件后写输出 |
| `run` | 运行一轮后等待 `check_interval_seconds`，再运行下一轮，并启动 dashboard；页面可暂停/恢复自动探测 |
| `server` | 母鸡模式，只提供 dashboard、配置下发和 agent 上报 API，不做任何本机测量 |
| `agent` | 探针模式，主动从 `server_url` 拉取 CF 段和扫描参数，在本机网络测量后上报给母鸡 |
| `history` | 输出学习状态和 POP 漂移历史 |
| `render` | 用已保存的当前入口重新生成输出文件 |

## 母鸡 + Agent

母鸡维护 CF 种子段、采样预算、Cloudflare 官方测速参数和 dashboard。Agent 不保存全局策略，不更新 Cloudflare DNS，只负责从自己的真实网络出口测量并上报。

母鸡启动：

```powershell
$env:CFAR_AGENT_TOKEN="CHANGE_ME_SHARED_TOKEN"
go run . server config.yaml
```

VPS 一键安装 agent：

```bash
curl -fsSL https://raw.githubusercontent.com/kuaichu/CFAnycastRouter/main/install.sh \
  | sudo bash -s -- --server http://10.0.0.234:19199 --id vps-hk-01 --carrier auto --token CHANGE_ME_SHARED_TOKEN
```

如果母鸡没有设置 `CFAR_AGENT_TOKEN`，agent 上报接口不强制鉴权。生产环境建议设置相同 token。

## 输出

支持：

- `hosts`
- `dnsmasq`
- `AdGuard Home rewrite`
- `SmartDNS`
- `CoreDNS`
- `Clash provider`
- `sing-box outbound`
- `Nginx stream upstream`

输出默认写到 `out/`。

## 构建

```powershell
go mod tidy
go test ./...
go build -o cf-router.exe .
```

如果旧进程正占用 `cf-router.exe`，先停掉旧进程，或临时构建为：

```powershell
go build -o cf-router-new.exe .
```
