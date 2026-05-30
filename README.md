# cproxy (C Implementation)

A lightweight, dependency-free C implementation of `cproxy` for transparently redirecting network traffic using cgroups and iptables.

## Relationship to the Original Rust Project
This project is a complete **C language rewrite/port** of the original [cproxy](https://github.com/NOBLES5E/cproxy) (which is written in Rust).

It was created to address and explore specific system-level mechanics that are complex to handle safely in Rust, specifically:
- **Flawless Privilege Dropping:** It explicitly uses `initgroups` alongside `getpwuid` to perfectly restore a user's supplementary groups (like `docker`) and environment variables (`HOME`, `USER`) after running under `sudo`.
- **Zero External Dependencies:** It interacts directly with the Linux kernel (libc, execvp, cgroup file I/O) without requiring heavy crates or a cargo build system.
- **Microscopic Footprint:** The compiled binary is typically under 50KB, making it ideal for extremely constrained environments.

This C version achieves feature parity with the core functionalities (Redirect, TProxy, Trace) of the Rust version while acting as a proof-of-concept for stricter environment and resource management.

## Features
- **Redirect Mode:** Redirect TCP and DNS (UDP/TCP) traffic.
- **TProxy Mode:** Transparently proxy TCP and UDP traffic with optional DNS overriding.
- **Trace Mode:** Trace application network activity (all protocols) using iptables LOG target.
- **Proxy Existing Processes:** Attach to an existing PID and proxy its traffic.
- **IP Bypass:** Ignore specific IP ranges (like local LANs) to prevent routing loops and proxying internal traffic.
- **Robust Process Management:** Uses a non-blocking polling mechanism (100ms) for ultra-responsive cleanup and process state monitoring.
- **Enhanced Observability:** Detailed verbose mode and **dry-run mode** for auditing system commands without execution.
- **Unified Architecture:** Refactored into a modular, context-driven design for better maintainability.
- **Improved Security:** Hardened cgroup v2 path resolution and strict privilege-dropping checks.
- **Microscopic Footprint:** Even with added robustness, the compiled binary remains under 50KB.

## Compilation

Requires `gcc` and `make`.

```bash
make
sudo make install
```
By default, it installs to `/usr/local/bin`. You can customize the location:
```bash
sudo make install PREFIX=/usr
```

## Usage

This tool must be run as root to modify cgroups and iptables.

### IPv6 Support
`cproxy` handles IPv6 differently depending on the mode:
- **Redirect Mode:** Outbound IPv6 traffic from the proxied process is **dropped** to prevent leaks (since NAT redirection for IPv6 is complex).
- **TProxy/Trace Mode:** Full IPv6 support is implemented. Traffic is transparently proxied or logged just like IPv4.
Bypass rules also support IPv6 CIDRs.

### Environment Variables and `sudo -E`
By default, running `sudo` strips almost all of your personal environment variables (like custom `PATH`, `NVM_DIR`, `GOPATH`, or IDE specific variables) for security reasons. `cproxy` will automatically restore your `HOME`, `USER`, and `LOGNAME` so that standard tools like `docker` or `git` work correctly.

However, if you are proxying a development tool (e.g., a Node.js script relying on `nvm` or a script relying on custom paths), you **must** use the `-E` flag with `sudo` to preserve your environment:
```bash
sudo -E ./cproxy --mode redirect --port 1080 -- <your-command>
```
*Security Note: Only use `-E` when you completely trust the application you are proxying.*

### Dry-Run Mode
See what commands `cproxy` would execute without actually modifying system state:
```bash
sudo ./cproxy --dry-run --mode tproxy --port 1080 -- <your-command>
```

### Redirect Mode
Redirect all TCP traffic (and optionally DNS) of a new command to a local transparent proxy port:
```bash
sudo ./cproxy --mode redirect --port 1080 --redirect-dns -- <your-command>
```

### TProxy Mode
Proxy all TCP and UDP traffic using TProxy (useful for V2Ray or Shadowsocks):
```bash
sudo ./cproxy --mode tproxy --port 1080 --override-dns 1.1.1.1 -- <your-command>
```

### Bypass Specific IPs
Use the `--bypass` flag to specify IP ranges (like LANs) that should be ignored by the proxy. Supports comma-separated CIDRs:
```bash
sudo ./cproxy --mode tproxy --port 1080 --bypass "192.168.0.0/16,10.0.0.0/8" -- <your-command>
```

### Proxy Existing Process
Attach to an already running process and redirect its traffic:
```bash
sudo ./cproxy --mode tproxy --port 1080 --pid 1234
```

## Architecture
The program creates an isolated cgroup `net_cls`, spawns the child process within it after dropping privileges back to the original user (restoring supplementary groups safely), and uses `iptables` and `ip rule` to intercept and route the traffic. Upon exit or termination (Ctrl+C), it uses signals and `atexit` hooks to cleanly remove all generated rules and cgroups.