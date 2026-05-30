# cproxy (C 语言实现)

这是一个极其轻量、零外部依赖的 `cproxy` C 语言实现，用于通过 cgroups 和 iptables 实现应用程序网络流量的透明重定向。

## 与原 Rust 项目的关系
本项目是原版 [cproxy](https://github.com/NOBLES5E/cproxy)（使用 Rust 编写）的完整 **C 语言重写/移植版**。

它的诞生主要是为了解决在 Rust 中处理某些底层系统机制时的安全与复杂度问题，具体包括：
- **完美的权限降级 (Privilege Dropping)**：在 `sudo` 环境下，本版本明确调用了 `initgroups` 和 `getpwuid`，可以完美恢复普通用户的附加组（例如 `docker` 组权限）以及环境变量（`HOME`、`USER`），这是 Rust 标准库较难优雅处理的痛点。
- **零外部依赖**：直接与 Linux 内核交互（libc、execvp、cgroup 文件 I/O），无需依赖庞大的 cargo 编译系统或第三方库。
- **极致的轻量化**：编译后的二进制文件通常小于 50KB，非常适合资源极度受限的嵌入式环境（如路由器）或容器基础镜像。

这个 C 版本在核心代理功能（Redirect, TProxy, Trace）上实现了与 Rust 版本的特性对齐，同时作为系统级资源和环境管理的绝佳技术验证。

## 功能特性
- **Redirect 模式:** 劫持并重定向 TCP 和 DNS UDP 流量。
- **TProxy 模式:** 透明代理 TCP 和 UDP 流量，支持 DNS 地址覆盖。
- **Trace 模式:** 利用 iptables LOG 目标追踪应用程序的网络活动。
- **接管运行中的进程:** 附加到一个已存在的 PID，代理其网络流量。
- **IP 豁免 (Bypass):** 支持不代理指定的 IP 网段（如内网局域网），防止路由死循环。
- **极度轻量:** 极小的内存占用，零外部依赖，毫秒级启动。
- **后台常驻兼容:** 能够智能检测 cgroup 进程树，完美兼容后台运行的守护进程。

## 编译指南

需要系统安装有 `gcc` 和 `make`。

```bash
make
```
此命令将使用极其严格的安全编译参数 (`-Wall -Wextra -Werror -O2`) 进行编译，最终生成一个单独的 `cproxy` 二进制文件。

## 使用方法

此工具必须以 root 权限运行，以便修改 cgroups 和 iptables 规则。

### 环境变量与 `sudo -E`
出于安全考虑，`sudo` 默认会清洗掉你大部分的个人环境变量（如自定义的 `PATH`，`NVM_DIR` 等）。`cproxy` 会智能地帮你恢复 `HOME`, `USER`, 和 `LOGNAME` 以保证 `docker` 或 `git` 等基础命令正常工作。

但是，如果你要代理的是一个重度依赖本地环境的开发工具（比如依赖 nvm 路径的 Node.js 脚本），你**必须**使用 `-E` 参数来保留你的环境变量：
```bash
sudo -E ./cproxy --mode redirect --port 1080 -- <你的命令>
```
*安全提示：仅在你完全信任目标程序时使用 `-E`，以免敏感变量泄露。*

### Redirect 模式
代理一个新命令的所有 TCP（和 DNS）流量至本地透明代理端口：
```bash
sudo ./cproxy --mode redirect --port 1080 --redirect-dns -- <你的命令>
```

### TProxy 模式
使用 TProxy 代理所有 TCP 和 UDP 流量（常用于 V2Ray 或 Shadowsocks 透明代理）：
```bash
sudo ./cproxy --mode tproxy --port 1080 --override-dns 1.1.1.1 -- <你的命令>
```

### 绕过特定网段 (Bypass IPs)
使用 `--bypass` 标志指定不希望被代理的局域网或公网 IP 段（支持逗号分隔多个 CIDR）：
```bash
sudo ./cproxy --mode tproxy --port 1080 --bypass "192.168.0.0/16,10.0.0.0/8" -- <你的命令>
```

### 代理已有进程
强制接管一个系统中已经运行的进程流量：
```bash
sudo ./cproxy --mode tproxy --port 1080 --pid 1234
```

## 架构说明
程序运行时会创建一个独立的 `net_cls` cgroup，在使用 `setuid`/`initgroups` 恢复原始用户权限后，将子进程生成在其中。接着通过 `iptables` 和 `ip rule` 拦截指定组的流量。当目标程序退出或用户按下 Ctrl+C 时，通过拦截信号和 `atexit` 钩子，程序会干净利落地清除所有已生成的网络规则和 cgroup 目录，绝不遗留系统垃圾。