# Linux Security Toolbox

一个面向 Linux 服务器的交互式安全审计与加固工具箱。项目包含主控台、审计、修复、SSH 密钥配置和禁 Ping 管理等模块，适合在自有服务器、授权运维或防御性安全检查场景中使用。

> ⚠️ 本工具会修改系统配置。运行前请确认你拥有服务器管理权限，并建议先创建快照或备份关键配置。

## 功能概览

| 脚本 | 模块 | 作用 | 默认风险 |
|------|------|------|----------|
| `install.sh` | 主控台 | 下载/更新、运行子脚本、本地自检、清理工具脚本 | 低 |
| `v0.sh` | 全维安全审计 | 只检查不修改，输出安全评分和修复建议 | 低 |
| `v1.sh` | 基础安全加固 | APT 源自动优化、基础工具兼容安装、BBR、SSH 低风险项、权限、内核、日志、Fail2ban | 中，交互确认 |
| `v2.sh` | SSH 策略中心 | 生成/部署 ED25519 密钥、修改 SSH 端口、密码登录策略、Root 登录策略、备份回滚 | 高，强确认 |
| `v3.sh` | 禁 Ping 管理 | 通过 sysctl / 防火墙管理 ICMP Echo（含 IPv6） | 中 |
| `v4.sh` | IPv6 出口中心 | Cloudflare WARP IPv4 出口、GitHub raw 加速 fallback 探测 | 高，明确操作才执行 |

## 快速开始

请使用具有 **root** 权限的终端执行。

### 官方源

```bash
wget -qO install.sh https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh
chmod +x install.sh
./install.sh
```

> 纯 IPv6 主机可以把上述 `wget` 改为 `wget -6`；如果使用 curl，请显式使用 `curl -6`。下载中心内部会自动选择地址族。
> 启动时如果 `lib/runtime.sh` 等核心组件缺失，主控台会尝试补齐；若 GitHub、中转站、DNS 或本机证书暂时不可用，下载失败不会再直接退出，也不会删除已有脚本。可以先进入主菜单，再到 `[9] 下载中心` 稍后重试。

### GitHub 访问困难时

```bash
wget -qO install.sh https://gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh
chmod +x install.sh
./install.sh
```

## 推荐使用流程

1. 先运行 `v0.sh` 做只读审计。
2. 根据报告确认风险项，不要盲目全选修复。
3. 运行 `v1.sh` 时按需选择项目；APT 源优化会自动备份、测速选择镜像并保留官方源兜底。
4. 如需修改 SSH 端口、关闭 SSH 密码登录或调整 Root 登录，请使用 `v2.sh` 的 SSH 策略中心。
5. 使用 `v2.sh` 执行高风险 SSH 策略前，务必保留当前窗口并新开 SSH 窗口测试登录成功。
6. 使用 `v3.sh` 禁 Ping 前，确认云厂商安全组、防火墙策略与你的监控方式兼容。

## 主控台菜单

`install.sh` 提供统一入口：

- `[0]` 全维审计：只查不改，输出评分。
- `[1]` 基础管家：APT 源优化、基础软件、低风险系统加固。
- `[2]` SSH 策略中心：密钥部署、改端口、密码登录、Root 登录和回滚。
- `[3]` 网络隐身：管理禁 Ping 策略。
- `[4]` IPv6 出口中心：检测 IPv4/IPv6 出口、安装/连接/断开 WARP、探测并设置 GitHub fallback。
- `[7]` 本地自检：检查脚本 Bash 语法。
- `[8]` 智能清理：清理本工具箱子脚本。
- `[9]` 下载中心：下载或更新子脚本。

## 本地验证

修改脚本后建议先运行：

```bash
bash -n install.sh lib/runtime.sh lib/network_checks.sh lib/github.sh v0.sh v1.sh v2.sh v3.sh v4.sh
```

如果已安装 shellcheck，也可以进一步检查：

```bash
shellcheck install.sh lib/runtime.sh lib/network_checks.sh lib/github.sh v0.sh v1.sh v2.sh v3.sh v4.sh
```

## 支持环境

- Debian / Ubuntu 系列
- CentOS / RHEL / Rocky / AlmaLinux 系列
- 需要 root 权限
- 部分功能依赖：`curl`、`wget`、`systemctl`、`iptables`、`nft`、`ufw`、`firewall-cmd` 等

脚本会尽量自适应环境；如果某些组件不存在，会跳过或提示手动处理。

## Debian/Ubuntu 兼容说明

`v1.sh` 会对常见工具做包名映射，例如：

- `fuser` → `psmisc`
- `ping` → `iputils-ping`
- `nslookup` → `dnsutils`，失败时尝试 `bind9-dnsutils`
- `ss` → `iproute2`
- `netstat` → `net-tools`

APT 源优化会备份 `/etc/apt/sources.list` 到：

```text
/etc/apt/sec_toolbox_sources_backup_时间戳/
```

脚本会根据网络环境在清华、中科大、阿里镜像中测速选择，并保留 Debian/Ubuntu 官方源作为兜底；如果 `apt-get update` 失败，会自动恢复备份。

## 风险提示

以下操作可能影响远程登录或业务连通性，请谨慎执行：

- `v2.sh` 中关闭 SSH 密码登录
- `v3.sh` 中修改防火墙/禁 Ping
- 手动修改 SSH 端口、禁止 root 登录、改写 DNS、清理 SUID、限制编译器或自动更新系统组件

为降低误用风险，上述高破坏性项目不再放入 `v1.sh` 一键加固列表。

## 免责声明

本项目仅用于自有系统、授权运维、防御性安全检查与学习研究。请勿在未授权系统上运行。

作者不对以下情况承担责任：

- 未备份导致的配置丢失
- 错误关闭 SSH 导致无法远程登录
- 网络、防火墙、DNS 配置变更造成业务中断
- 特殊发行版或云厂商镜像差异导致的不可预期行为

## 贡献与反馈

如果你在运行中遇到 Bug，或有更好的功能建议，欢迎提交 Issues。

如果这个项目帮到了你，欢迎 Star 支持持续迭代。

## 纯 IPv6 VPS 支持

### 下载问题

纯 IPv6 VPS 不能访问 IPv4-only 下载端点；内网双栈主机也可能因为 DNS、证书、代理或 GitHub 可达性导致初始化下载失败。现在下载中心会：

- 纯 IPv6 环境自动使用 `curl -6` 或 `wget -6`，并跳过 IPv4-only 中转。
- 优先尝试已验证/已缓存的 GitHub 中转和当前地址族可用中转，GitHub 官方 raw / 原始地址作为最后备选。
- 下载到临时文件并通过 `<SEC_SCRIPT_MARKER_v2.3>` 特征码校验后才替换目标文件；失败时保留已有本地脚本，不再先删文件。
- 启动初始化只补齐缺失组件；单个组件下载失败会提示原因并跳过失败项，继续进入主菜单，不再因为 `lib/runtime.sh` 一项失败直接退出。
- 可以在 `[9] 下载中心` 反复重试；下载失败不会破坏已可用的本地脚本。

### `ICMP(阻断)` 与 `DNS(阻断)` 是什么

旧版本的状态来自主动出站探测，不等于已经证明“本机防火墙阻断”。

`ICMP(阻断)` 可能表示：

- 云厂商、上游网络或安全组禁止 ICMP；
- 目标地址不回应 ping；
- 本机没有对应 IP 家族的默认路由；
- 纯 IPv6 VPS 被错误地使用 IPv4 目标测试；
- `ping` 缺失或网络策略不允许探测。

`DNS(阻断)` 可能表示：

- `getent`、`resolvectl` 或 `nslookup` 等工具缺失；
- 旧逻辑硬编码 IPv4 DNS，纯 IPv6 VPS 无法访问；
- `/etc/resolv.conf`、systemd-resolved 或上游 DNS 配置异常；
- DNS 服务暂时不可用。

新版本会先识别 `pure_ipv6`、`dual_stack` 或 `ipv4_only`，再选择合适的 ICMP/TCP 地址族；DNS 优先通过系统 resolver 检查，不再把一次失败直接显示为本机阻断。

### 是否应该在最开始自动修复

不建议启动时自动修改 ICMP、防火墙或 DNS。正确的流程是：

1. 先执行只读审计和网络诊断；
2. 确认 IP 模式与失败原因；
3. 只有在用户明确选择后，才通过 `v3.sh` 修改内核 ICMP 或防火墙规则；
4. 只有确认 resolver 配置确实有问题时，才人工修复 DNS；
5. 修改 SSH、DNS 或防火墙前保留当前会话，并使用脚本生成的备份。

特别是纯 IPv6 VPS，不能因为 ping 失败就自动开启/关闭防火墙，也不能把 DNS 改成只能通过 IPv4 访问的服务器。这样做可能反而让下载、更新和远程维护完全中断。

### 进程锁与包管理器锁

- `v0.sh`、`v1.sh`、`v2.sh`、`v3.sh` 共用 toolbox 进程锁。
- 优先使用 `flock`；没有 `flock` 时使用带 PID 的原子 `mkdir` fallback，并回收确认已退出进程留下的 stale lock。
- `apt`、`apt-get`、`dpkg`、`unattended-upgrade`、`dnf`、`yum` 和 `rpm` 操作前会等待正在运行的包管理器，并通过独立的包操作锁串行化。
- 不删除 `/var/lib/dpkg/lock*` 等系统原生锁文件；如果包管理器长时间运行，会提示稍后重试。

## 纯 IPv6 出口与 GitHub 加速中心（v4.sh）

`v4.sh` 不会在启动时安装、注册或连接 WARP，也不会自动改写 DNS。所有会改变网络路由的动作都必须由用户在菜单中明确选择，并且每个网络命令都有超时。

### Cloudflare WARP 两种系统出口模式

- **全隧道**：IPv4 和 IPv6 都交给 WARP，适合只需要系统级 IPv4 出口、且接受 IPv6 也经 WARP 的场景。
- **IPv4-only / 部分接管**：仍使用 WARP 全隧道配置，但通过当前 `warp-cli` 实际公开的分流命令加入 IPv6 `::/0` 排除路由；结果是 IPv4 走 WARP，IPv6 保留 VPS 原生出口。脚本不会凭猜测写路由：先检查 `warp-cli help` 是否支持 `tunnel ip`（旧版本若公开 `add-excluded-route` 也兼容），不支持时直接拒绝修改。
- 选中全隧道时会先检测并移除 IPv4-only 的 IPv6 排除路由；重复执行 IPv4-only 时会检测已有 `::/0`，不会重复添加。
- 状态检测会区分“已注册、全隧道、已连接、IPv4 出口正常、IPv4-only 分流已存在”，不会把一次失败变成无限重连，也不会自动修改 DNS。
- WARP 提供共享 IPv4 出口，不是入站公网 IPv4；SSH 入站仍依赖原有 IPv6。连接前请保留当前 SSH 会话和控制台回滚路径。

### GitHub 中转站与下载优先级

GitHub 下载现在按下面顺序处理：

1. 已保存并通过检测的多个 GitHub 中转站，按优先级依次尝试；
2. 当前地址族可用的其他中转站；
3. GitHub 官方 raw / GitHub 原始地址作为**最后备选**。

已加入并按 URL 形态处理的候选包括：

- `gh-proxy.com`
- `gh-proxy.org`
- `v4.gh-proxy.org`（仅 IPv4）
- `v6.gh-proxy.org`（仅 IPv6）
- `cdn.gh-proxy.org`
- `axisnow.gh-proxy.org`
- 原有 `ghproxy.net`、`ghfast.top`

`axisnow` 等站点不再被当成统一固定前缀：下载函数支持将 raw 路径转换为完整 `https://raw.githubusercontent.com/...` URL，也支持直接传入 GitHub release 完整 URL，例如用户提供的 frp release 示例。不同中转站格式如有变化，会因为特征码校验失败而被跳过，不会把 HTML 错误页当成脚本。

### 多轮检测、自动选择与幂等缓存

- 默认每个候选检测 **3 轮**，至少成功 **2 轮**才算可用；可用环境变量 `SEC_GITHUB_PROBE_ROUNDS`、`SEC_GITHUB_PROBE_MIN_SUCCESS` 调整。
- 检测不是只看 HTTP 200：必须下载仓库 `install.sh` 并匹配 `<SEC_SCRIPT_MARKER_v2.3>` 特征码；纯 IPv6 主机会强制 `curl -6` / `wget -6`。
- 自动选择会先按当前 IPv4/IPv6 地址族过滤，再按多轮成功次数排序；成功次数相同时保留内置优先级。它会把所有达到最低成功次数的中转保存为优先级列表，而不是只保存一个站点。
- 手动选择支持逗号分隔的多个编号，例如 `2,4,6`；官方 raw 固定作为最后备选，不能被保存成中转优先级。
- `/etc/sec-toolbox/github-endpoint` 保存中转优先级列表；同名 `.cache` 保存最近验证时间。缓存有效期默认 600 秒，重复运行会跳过不必要的探测和写入；下载成功后会原子更新成功站点到优先位置。
- `install.sh` 的最早期 bootstrap 也读取这个列表，因此在 `lib/github.sh` 尚未下载时，纯 IPv6 拉取 `v0.sh`～`v4.sh` 和公共库仍能复用已验证中转。

菜单新增：

- `IPv4-only WARP`
- `多轮探测 GitHub 中转站`
- `手动选择多个 GitHub 中转优先级`
- `自动选择可用 GitHub 中转（多轮）`

请不要把公共中转站当成 GitHub 权威来源。生产环境建议固定提交版本，并继续核对脚本特征码或哈希。
