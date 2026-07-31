# cproxy-c

`cproxy-c` is a highly lightweight, zero-dependency C utility designed to transparently redirect network traffic of specific Linux processes using **cgroups** and **iptables/tproxy**.

## Why `cproxy-c`? (vs. Proxychains)

Traditional tools like `proxychains` rely on `LD_PRELOAD` to hook socket functions. This approach **completely fails** for statically linked binaries (e.g., Go, Rust) and complex multi-process applications.

`cproxy-c` solves this by using Linux kernel features (`cgroup` routing) to achieve **true network-layer transparent proxying**. If a process is launched by `cproxy-c`, **all of its traffic** (including statically linked binaries, DNS, and subprocesses) is intercepted at the kernel level.

### Key Advantages
*   **Robust Privilege Dropping:** Safely elevates to root to set up rules, then flawlessly drops privileges back to the original user (restoring `HOME`, `USER`, and supplementary groups like `docker`).
*   **Zero Dependencies:** Directly interacts with Linux system calls and iptables. No heavy build tooling required.
*   **Micro Footprint:** Compiled binary is **under 50KB**, perfect for embedded routers or resource-constrained containers.
*   **Sanitizer & Debugger Friendly:** Because it does not use `LD_PRELOAD` or inject any code into the target process's memory space, you can flawlessly run applications compiled with **Address Sanitizer (ASan)**, **Valgrind**, or under **GDB**. (Proxychains notoriously crashes ASan-instrumented binaries due to libc interception conflicts).

---

## Features

* **Redirect Mode:** Intercepts outbound TCP and REDIRECTs it to a local port. Drops IPv6 to prevent leaks.
* **TProxy Mode (Bidirectional-Safe):** Transparently proxies TCP and UDP outbound traffic (IPv4/IPv6) with optional DNS override. Through flow-directional Conntrack marking, inbound connections to server applications running inside the cgroup are preserved and bypassed, allowing you to proxy server processes safely!
* **Trace Mode:** Audits and logs application network activity in real time using the `iptables LOG` target.
* **Process Attaching:** Dynamically intercepts traffic of an already running process via `--pid`.
* **Bypass /etc/hosts & /etc/resolv.conf:** Bind mount custom files (or `/dev/null`) to strictly force/bypass DNS resolution via `--hosts <file>` and `--resolvconf <file>`.
* **Bypass Rules:** Bypass specific IP ranges (e.g., LAN) to prevent routing loops.
* **Garbage Collection:** Auto-cleans orphaned cgroups and stale iptables rules (`--clean`).

---

## Installation

```bash
git clone https://github.com/icsfy/cproxy-c.git
cd cproxy-c
make
sudo make install
```

---

## Practical Usage Guide

`cproxy-c` is a routing wrapper. **It does not provide the proxy server itself.** You must run a proxy core (like Xray, V2Ray, Shadowsocks, or sing-box) listening on a local port.

### 1. Transparent Proxying (TCP & UDP) with Xray/V2Ray
If your Xray core is running locally with a `dokodemo-door` (or `tproxy`) inbound on port `1080`:

```bash
sudo ./cproxy --mode tproxy --port 1080 --override-dns 8.8.8.8 -- curl https://api.ipify.org
```
*Note: We highly recommend using `--override-dns` to prevent local DNS requests (e.g., to systemd-resolved) from bypassing the proxy and leaking your queries.*

### 2. Transparent Proxying with Gost (v3)
`gost` is an excellent, lightweight tunneling proxy. Start a Gost TProxy listener on port `1080`:
```bash
gost -L tproxy://:1080
```
Then route a process through it using `cproxy-c`:
```bash
sudo ./cproxy --mode tproxy --port 1080 --override-dns 8.8.8.8 -- curl https://api.ipify.org
```

### 3. Simple TCP Redirection
If your proxy core only supports simple REDIRECT (or you don't need UDP):
```bash
sudo ./cproxy --mode redirect --port 1080 --redirect-dns -- npm install
```

### 4. Bypassing LAN / Localhost
Prevent routing loops by bypassing your proxy server's IP or local subnets:
```bash
sudo ./cproxy --mode tproxy --port 1080 --bypass "192.168.0.0/16,10.0.0.0/8" -- <command>
```

### 5. Attaching to a Running Daemon (e.g., Docker)
Take over the traffic of a currently running process.
```bash
sudo ./cproxy --mode tproxy --port 1080 --pid $(pidof dockerd)
```
*(Warning: Existing established connections will not be proxied. Only new connections will be routed.)*

### 6. Strict DNS Isolation (Bypassing /etc/hosts & /etc/resolv.conf)
You can isolate the proxied process in a mount namespace and provide a custom `/etc/hosts` or `/etc/resolv.conf`. This is the cleanest way to completely bypass the host's `systemd-resolved` and force standard DNS queries without relying on iptables DNAT:
```bash
# Force the application to natively query 8.8.8.8 instead of the host's 127.0.0.53
echo "nameserver 8.8.8.8" > my_resolv.conf
sudo ./cproxy --mode tproxy --port 1080 --resolvconf my_resolv.conf --hosts /dev/null -- curl http://local-domain
```

### 7. Cleaning up stale rules
If `cproxy-c` crashes unexpectedly, clean up orphaned iptables rules and cgroups:
```bash
sudo ./cproxy --clean
```

---

## Environment Preservation (`sudo -E`)

Because `cproxy` requires `sudo`, user environment paths are often stripped. `cproxy` automatically restores `HOME`, `USER`, `LOGNAME`, and `XDG_RUNTIME_DIR`.

However, if your command relies on complex paths (like `nvm` node paths), you should use `sudo -E`:
```bash
sudo -E ./cproxy --mode redirect --port 1080 -- node script.js
```

---

## Architecture

```text
                  +--------------------------------+
                  |      cproxy Host Process       |
                  |  (Creates cgroup & iptables)   |
                  +---------------+----------------+
                                  |
                                  v (fork & drop privileges)
                  +---------------+----------------+
                  |         Target Process         |
                  |  (Runs in isolated cgroup)     |
                  +---------------+----------------+
                                  | (Outbound Traffic)
                                  v
                  +---------------+----------------+
                  |    Netfilter / iptables        |
                  |  (Matches cgroup -> Redirect)  |
                  +---------------+----------------+
                                  |
                                  v
                  +---------------+----------------+
                  |    Local Proxy Port (1080)     |
                  +--------------------------------+
```

---

## Security & Anonymity Limitations

`cproxy-c` is a highly convenient tool designed to transparently proxy applications for development, network accessibility, or bypass restrictions. However, due to the structural decoupling of process lifecycle, socket lifecycle, and packet generation in the Linux kernel, **it is NOT recommended as an anonymity tool (like Tor)**. Users requiring strict anonymity should use network namespaces (netns) or dedicated VMs.

1. **Subprocess Cgroup Escapes (e.g., Docker, Systemd)**: `cproxy-c` relies on Cgroup process trees. If you run a process that proactively manipulates its own Cgroups (e.g., `dockerd` spawning containers, or `systemctl` starting a service), the child processes are often moved to a completely different Cgroup by the daemon. Their traffic will **silently escape** the proxy. Attaching to `dockerd` will NOT proxy the containers it spawns!
2. **TCP RST & Orphan Socket Leak**: When a process exits or crashes, the kernel closes its sockets, transitioning them to orphan states (e.g. `TIME_WAIT`) and automatically sending TCP `FIN` or `RST` packets. At this stage, the cgroup context might be lost, causing these trailing packets to bypass the proxy and travel directly to the destination using your real IP, potentially leaking your identity to the target server.
3. **`--pid` Mode Initialization Gap**: Sockets are bound to a cgroup *only at the time of creation* (`sk_alloc`). If you attach `cproxy-c` to an already running process using `--pid`, its previously established connections and listening sockets will NOT be migrated and will bypass the proxy. Only newly created connections will be proxied.
4. **DNS Delegation (systemd-resolved)**: If an application delegates DNS resolution by connecting to a local stub resolver (e.g., `127.0.0.53:53`), proxying that request without providing an explicit `--override-dns` will result in a silent leak (where the host resolves it natively). Ensure you use `--override-dns` if you expect DNS traffic to remain strictly within the proxy tunnel.