# cproxy (C Implementation)

A lightweight, dependency-free C implementation of `cproxy` for transparently redirecting network traffic using cgroups and iptables.

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