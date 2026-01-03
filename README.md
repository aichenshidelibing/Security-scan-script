# 🛡️ Linux Security Toolbox & Genesis Manager
> **全维度 Linux 安全审计，自动化加固与性能优化全能管家**

[![Bash Shell](https://img.shields.io/badge/Language-Bash%20Shell-4EAA25.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20CentOS%20%7C%20RHEL-blue.svg)](https://linux.org/)
[![Status](https://img.shields.io/badge/Status-Maintained-brightgreen.svg)]()

本工具箱致力于为 Linux 服务器提供从 **硬件体检、环境初始化、救砖换源** 到 **36 项深度加固** 的一站式全自动化解决方案。特别针对小白用户优化，内置智能环境自愈逻辑，杜绝弹窗卡死与环境闪退。

---

## ✨ 核心特性

### 🔍 v0.sh - 全维度安全审计 (检测版)
* **硬件信息仪表盘**：实时展示 CPU 型号/核心、内存使用、硬盘占用、系统内核及运行时间。
* **36 项全量检测**：完美对齐加固项，涵盖 SSH 安全、账户权限、内核参数及全量漏洞审计。
* **可视化评分系统**：动态进度条展示安全分数，直观评估系统健康度。
* **风险建议回显**：针对扫描失败的项目，提供通俗易懂的“小白化”修复建议。

### 🛠️ v1.sh - 创世纪全能管家 (修复版)
* **老系统救砖 (EOL Rescue)**：自动识别并修复 CentOS 7、Debian 8/9/10 等停更系统的软件源 (Vault/Archive)。
* **极致性能飞跃**：一键开启 **TCP BBR 加速** 与 **智能 DNS 路由优化**，显著提升下载与访问速度。
* **批量软件安装**：一次性极速预装 `curl`, `wget`, `vim`, `htop`, `git`, `net-tools` 等必备工具。
* **环境自愈逻辑**：引入 `UCF/DPKG` 强制非交互模式，自动修复损坏的包管理器，彻底告别弹窗卡死。

### 🖥️ install.sh - 终极主控台
* **智能 UI 仪表盘**：主界面置顶显示实时 IP、系统版本、当前用户与服务器时间。
* **细化下载中心**：支持二级菜单化管理，可一键更新全部脚本或单独获取指定子脚本。
* **状态感知系统**：动态检测本地工具包的完整性，并提供清晰的功能子路径描述。

---

## 🚀 快速开始

请使用具有 **root** 权限的终端执行以下一键安装命令：

```bash
# GitHub 官方源 (推荐)：
wget -qO install.sh https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh
```
```bash
如果你在访问 GitHub 时遇到困难，可以使用加速镜像：
wget -qO install.sh https://gh-proxy.org/https://raw.githubusercontent.com/aichenshidelibing/Security-scan-script/refs/heads/main/install.sh
```
```bash
下载后如何使用，请看这里：
chmod +x install.sh && ./install.sh
```
⚠️ 免责声明
本工具涉及系统底层配置修改，运行前请务必做好 服务器快照或核心数据备份。

对于因系统环境极端特殊或硬件架构限制导致的不可预知情况，作者不承担法律责任。

漏洞补丁与软件更新受网络质量影响，若遇到超时请检查 DNS 或尝试切换源站。


🤝 贡献与反馈
如果你在运行中遇到任何 Bug 或有更好的功能建议，欢迎提交 Issues。

⭐ 如果这个项目帮到了你，请给一个 Star，这是项目持续迭代的最大动力！
