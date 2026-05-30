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
- **Redirect Mode:** Redirect TCP and DNS UDP traffic.
- **TProxy Mode:** Transparently proxy TCP and UDP traffic with optional DNS overriding.
- **Trace Mode:** Trace application network activity using iptables LOG target.
- **Proxy Existing Processes:** Attach to an existing PID and proxy its traffic.
- **Lightweight:** Minimal memory footprint, zero external dependencies, and lightning-fast execution.

## Compilation

Requires `gcc` and `make`.

```bash
make
```
This will compile the project with strict flags (`-Wall -Wextra -Werror -O2`) into a single `cproxy` binary.

## Usage

This tool must be run as root to modify cgroups and iptables.

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

### Proxy Existing Process
Attach to an already running process and redirect its traffic:
```bash
sudo ./cproxy --mode tproxy --port 1080 --pid 1234
```

## Architecture
The program creates an isolated cgroup `net_cls`, spawns the child process within it after dropping privileges back to the original user (restoring supplementary groups safely), and uses `iptables` and `ip rule` to intercept and route the traffic. Upon exit or termination (Ctrl+C), it uses signals and `atexit` hooks to cleanly remove all generated rules and cgroups.