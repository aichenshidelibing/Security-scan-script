# Linux Security Toolbox

一个面向 Linux 服务器的交互式安全审计与加固工具箱。项目包含主控台、基础加固、SSH 密钥配置和禁 Ping 管理等模块，适合在自有服务器、授权运维或防御性安全检查场景中使用。

> ⚠️ 本工具会修改系统配置。运行前请确认你拥有服务器管理权限，并建议先创建快照或备份关键配置。

## 功能概览

| 脚本 | 模块 | 作用 | 默认风险 |
|------|------|------|----------|
| `install.sh` | 主控台 | 下载/更新、运行子脚本、本地自检、清理工具脚本 | 低 |
| `v1.sh` | 基础安全加固 | APT 源自动优化、基础工具兼容安装、BBR、SSH 低风险项、权限、内核、日志、Fail2ban | 中，交互确认 |
| `v2.sh` | SSH 策略中心 | 生成/部署 ED25519 密钥、修改 SSH 端口、密码登录策略、Root 登录策略、备份回滚 | 高，强确认 |
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

1. 运行 `v1.sh` 时按需选择项目；APT 源优化会自动备份、测速选择镜像并保留官方源兜底。
2. 如需修改 SSH 端口、关闭 SSH 密码登录或调整 Root 登录，请使用 `v2.sh` 的 SSH 策略中心。
3. 使用 `v2.sh` 执行高风险 SSH 策略前，务必保留当前窗口并新开 SSH 窗口测试登录成功。
4. 使用 `v3.sh` 禁 Ping 前，确认云厂商安全组、防火墙策略与你的监控方式兼容。

## 主控台菜单

`install.sh` 提供统一入口：

- `[1]` 基础管家：APT 源优化、基础软件、低风险系统加固。
- `[2]` SSH 策略中心：密钥部署、改端口、密码登录、Root 登录和回滚。
- `[3]` 网络隐身：管理禁 Ping 策略。
- `[7]` 本地自检：检查脚本 Bash 语法。
- `[8]` 智能清理：清理本工具箱子脚本。
- `[9]` 下载中心：下载或更新子脚本。

## 本地验证

修改脚本后建议先运行：

```bash
for script in install.sh v1.sh v2.sh v3.sh v4.sh lib/*.sh platforms/*.sh tests/*.sh; do
    bash -n "$script" || exit 1
done
awk -f lib/apt-rewrite.awk /dev/null
bash tests/platform-apt-bbr.sh
bash tests/regression.sh
```

如果已安装 shellcheck，也可以进一步检查：

```bash
shellcheck install.sh v1.sh v2.sh v3.sh v4.sh
```

回归测试使用临时目录和模拟服务命令，不会修改系统 SSH、防火墙或安装软件；
若已安装 `/usr/sbin/sshd`，还会检查临时配置的实际展开结果。

### SSH 策略说明

- 修改端口、部署公钥、密码策略、Root 策略和推荐策略会保留其他托管配置。
- 每次变更生成独立备份；配置校验或服务重载失败时尝试回滚。
- 如其他 Include 文件仍声明额外 Port，修改端口会拒绝并回滚，不会偷偷保留旧监听端口。
- 活动的 `ssh.socket` / `sshd.socket` 由 systemd 管理监听端口，本工具拒绝直接改端口，请通过控制台单独调整。
- `sshd -T` 展示全局配置，不代表所有用户的 `Match` 条件或真实网络可达性；务必在新窗口验证登录。

## 支持环境

- 适配白名单：Debian 11/12/13，Ubuntu LTS 20.04/22.04/24.04/26.04
- RPM 系：RHEL / Rocky / AlmaLinux 8/9/10，CentOS Stream 9/10；保留各自官方仓库，不使用 APT 换源
- 这是适配目标，不是完整真机认证列表；离线测试覆盖系统识别与配置生成，安装软件等仍依赖各发行版仓库
- 老旧系统、未知衍生系统默认拒绝自动套用配置；Ubuntu 20.04 的扩展安全维护需自行配置 Ubuntu Pro/ESM
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

### 镜像选择与回滚

国内候选仅保留三家：

- 清华：`https://mirrors.tuna.tsinghua.edu.cn`
- 阿里：`https://mirrors.aliyun.com`
- 腾讯：`https://mirrors.cloud.tencent.com`

不预设某家全国最快，也不依赖 IP 定位。运行时在目标服务器对对应发行版的
`InRelease` 下载三次，以中位耗时排序；这是元数据传输耗时，不等同于大软件包吞吐量。
返回错误、架构不符或不是签名元数据的候选会跳过。按排名在临时配置和全新索引目录中
执行 APT 严格更新、签名验证；失败尝试下一家，最后尝试官方源。所有候选失败则不改源。

支持传统 `.list` 与 DEB822 `.sources`，保留原有组件、签名密钥、架构选项与第三方仓库。
混合不同发行版的套件、无法安全处理的配置会拒绝自动修改。Ubuntu ARM 等使用
`ubuntu-ports`；安全更新默认保留官方源，避免镜像同步延迟。

不把镜像和官方的同一套件重复写入；“兜底”是在应用前验证并选择候选，不是 APT 下载时自动切换。
配置提交前备份实际变动文件至 `/var/backups/sec-toolbox/apt/sources_*/`；提交后的
严格刷新失败会恢复原配置。普通软件安装刷新失败不会擅自触发换源。
APT 换源默认不选中；签名检查始终保留，不使用 `trusted=yes` 绕过验证。

### 自适应 BBR

实现参考 Google BBR 的算法注册方式，以及 Teddysun、Linux-NetSpeed 的管理思路，
不自动执行远程脚本，不复制其换内核/修改 GRUB/重启流程。

1. 默认不选中，执行时额外输入 `ENABLE BBR`。
2. 拒绝在可识别的容器内修改共享内核。
3. 尝试加载当前运行内核已安装的 `tcp_bbr` / `tcp_bbr2` / `tcp_bbr3` 模块。
4. 保留已经启用的 BBR；否则按明确注册名称 `bbr3`、`bbr2`、`bbr` 顺序选择。
5. 检查已有 sysctl 冲突，备份运行值和托管文件，应用后读回验证；失败恢复。
6. 写入 `/etc/sysctl.d/99-zz-sec-toolbox-bbr.conf`，备份位于 `/var/backups/sec-toolbox/bbr/`。

**不宣称自动选择了“该内核能运行的最高 BBR 代际”。** Google 的 BBRv3 源码仍可注册为
`bbr`；版本号、模块名和 `uname -r` 都不足以准确推断。现有内核没有 BBR 时停止并提示升级，
不下载不匹配的 `.ko`，不自动更换第三方内核。模块发现可能加载额外模块，失败回滚不卸载模块。
`fq` 默认值不表示既有网卡队列立即改变，且开启 BBR 不保证所有链路提速。

### 按系统下载

```text
install.sh                 系统识别、下载和主菜单
v1.sh                      公共基础加固
lib/platform.sh            发行版白名单和适配加载
lib/apt.sh                 三家镜像排序、验证和回滚
lib/apt-rewrite.awk         保留原格式的源改写
lib/bbr.sh                 当前内核 BBR 检测与配置
platforms/debian.sh         Debian 版本、仓库和架构规则
platforms/ubuntu.sh         Ubuntu LTS / ubuntu-ports 规则
platforms/rhel.sh           RPM 系隔离边界，保留厂商仓库
v2.sh / v3.sh / v4.sh       公共模块，不复制为多套
```

安装器先读取 `/etc/os-release`，只下载当前系统的一个适配文件及公共依赖。
直接使用 `v1.sh` 必须保留 `lib/` 和相应 `platforms/` 文件；旧版单文件部署请从下载中心更新。
`--local` 不下载缺失依赖。下载校验检查标记与语法，不等同于密码学签名校验。

### 查阅资料

- [清华 Ubuntu 帮助（含 ARM、DEB822、安全源说明）](https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/)
- [清华 Debian 帮助](https://mirrors.tuna.tsinghua.edu.cn/help/debian/)
- [阿里 Ubuntu 帮助](https://developer.aliyun.com/mirror/ubuntu)
- [腾讯 Ubuntu 帮助](https://mirrors.cloud.tencent.com/help/ubuntu.html)
- [Google BBR](https://github.com/google/bbr)、[BBRv3 注册源码](https://github.com/google/bbr/blob/v3/net/ipv4/tcp_bbr.c)
- [Teddysun BBR](https://github.com/teddysun/across/blob/master/bbr.sh)
- [Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

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
