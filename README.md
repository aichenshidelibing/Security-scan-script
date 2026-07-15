# Linux Security Toolbox

一个面向 Linux 服务器的交互式安全审计与加固工具箱。项目包含主控台、审计、修复、SSH 密钥配置和禁 Ping 管理等模块，适合在自有服务器、授权运维或防御性安全检查场景中使用。

> ⚠️ 本工具会修改系统配置。运行前请确认你拥有服务器管理权限，并建议先创建快照或备份关键配置。

## 功能概览

| 脚本 | 模块 | 作用 | 默认风险 |
|------|------|------|----------|
| `install.sh` | 主控台 | 下载/更新、运行子脚本、本地自检、清理工具脚本 | 低 |
| `v0.sh` | 全维安全审计 | 只检查不修改，输出安全评分和修复建议 | 低 |
| `v1.sh` | 基础安全加固 | BBR、基础工具、SSH 低风险项、权限、内核、日志、Fail2ban | 中，交互确认 |
| `v2.sh` | SSH 密钥配置 | 生成 ED25519 密钥、部署公钥、可选关闭密码登录 | 高，需确认 |
| `v3.sh` | 禁 Ping 管理 | 通过 sysctl / 防火墙管理 ICMP Echo | 中 |

## 快速开始

请使用具有 **root** 权限的终端执行。

### 官方源

```bash
wget -qO install.sh https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh
chmod +x install.sh
./install.sh
```

### GitHub 访问困难时

```bash
wget -qO install.sh https://gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh
chmod +x install.sh
./install.sh
```

## 推荐使用流程

1. 先运行 `v0.sh` 做只读审计。
2. 根据报告确认风险项，不要盲目全选修复。
3. 运行 `v1.sh` 时按需选择项目；容易锁死或破坏业务的项目已从一键加固中剔除。
4. 如需关闭 SSH 密码登录，请使用 `v2.sh` 的手动确认流程，并确保已有可用的备用登录方式。
5. 使用 `v2.sh` 关闭密码登录前，务必新开 SSH 窗口测试密钥登录成功。
6. 使用 `v3.sh` 禁 Ping 前，确认云厂商安全组、防火墙策略与你的监控方式兼容。

## 主控台菜单

`install.sh` 提供统一入口：

- `[0]` 全维审计：只查不改，输出评分。
- `[1]` 全能管家：交互选择加固项。
- `[2]` 密钥配置：生成并部署 SSH 密钥。
- `[3]` 网络隐身：管理禁 Ping 策略。
- `[7]` 本地自检：检查脚本 Bash 语法。
- `[8]` 智能清理：清理本工具箱子脚本。
- `[9]` 下载中心：下载或更新子脚本。

## 本地验证

修改脚本后建议先运行：

```bash
bash -n install.sh v0.sh v1.sh v2.sh v3.sh
```

如果已安装 shellcheck，也可以进一步检查：

```bash
shellcheck install.sh v0.sh v1.sh v2.sh v3.sh
```

## 支持环境

- Debian / Ubuntu 系列
- CentOS / RHEL / Rocky / AlmaLinux 系列
- 需要 root 权限
- 部分功能依赖：`curl`、`wget`、`systemctl`、`iptables`、`nft`、`ufw`、`firewall-cmd` 等

脚本会尽量自适应环境；如果某些组件不存在，会跳过或提示手动处理。

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
