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

纯 IPv6 VPS 不能访问 IPv4-only 下载端点。现在下载中心会：

- 优先使用 `raw.githubusercontent.com`；纯 IPv6 环境自动使用 `curl -6` 或 `wget -6`。
- 依次尝试官方 raw、GitHub raw path，最后才使用代理 fallback。
- 在下载 `v0.sh` 到 `v3.sh` 前，同步下载 `lib/runtime.sh` 和 `lib/network_checks.sh`。
- 任意核心脚本或公共库缺失时，初始化流程会先补齐公共库，再下载子脚本。

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

`v4.sh` 不会在启动时安装、注册或连接 WARP，也不会自动改写 DNS。所有会改变网络路由的动作都在菜单中单独确认。

### Cloudflare WARP

- 安装阶段只使用 Cloudflare 官方软件源 `pkg.cloudflareclient.com`；Debian/Ubuntu 通过现有包管理器锁串行执行 APT。
- “注册并连接”使用 **WARP 全隧道模式**，用于提供系统级 IPv4 出口；`warp-cli mode proxy` 只提供本地代理，不能当作系统 IPv4 出口，所以本项目不把它作为默认修复方案。
- WARP 提供的是共享的 IPv4 出口，不是给 VPS 分配一个可入站访问的公网 IPv4 地址；SSH 入站仍依赖原有 IPv6 地址。
- WARP 可能改变默认路由、影响 SSH、云安全组、源站访问和已有防火墙策略。连接前请保留当前 SSH 会话，并准备 `v4.sh` 的“断开 WARP”或控制台回滚方案。
- 安装 WARP 需要主机先能通过 IPv6 访问 Cloudflare 官方软件源；如果本机连 IPv6 默认路由都没有，脚本不会伪造修复，而是明确报错。
- 安装、连接和状态探测都有超时，不会无限等待。连接后仍会分别检查 IPv4 和 IPv6，避免把“IPv4 已恢复”误报成“IPv6 也正常”。

### GitHub 加速 fallback

下载顺序固定为：

1. `raw.githubusercontent.com` 官方 raw；
2. 已保存且当前可探测的 fallback；
3. 其他候选站点。

当前候选包括 `gh-proxy.org`、`ghproxy.net`、`ghfast.top` 和 `gh-proxy.com`。它们都是**动态探测候选**，不是永久承诺：域名解析、IPv6、证书、限流和 URL 格式都可能改变。`v4.sh` 会对仓库 `install.sh` 的特征码执行 HTTPS + IPv6 探测，只有探测通过才允许保存。纯 IPv6 主机请求会强制传递 `curl -6` / `wget -6`；官方 raw 永远保留第一优先级。

请不要把加速站当作 GitHub 权威来源，也不要把未通过探测的站点硬编码成唯一下载地址。对于敏感更新，建议优先固定提交版本并核对脚本特征码或哈希。

### 这两个“方案”的边界

- WARP 解决的是“主机没有 IPv4 出口”这一网络路径问题；它不能保证所有服务都允许 WARP 出口，也不能提供入站公网 IPv4。
- GitHub 加速解决的是“当前 IPv6 到 GitHub raw 不稳定/不可达”的下载路径问题；它不能修复本机 DNS、云厂商安全组或上游 IPv6 路由。
- 如果 WARP 已连接但 GitHub 仍失败，`v4.sh` 会分别探测 IPv4/IPv6 和各 raw endpoint，避免将不同原因混成 `DNS(阻断)`。
