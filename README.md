# cproxy (C Implementation)

`cproxy` is a highly lightweight, zero-dependency C utility designed to transparently redirect network traffic of specific processes using Linux **cgroups** and **iptables/tproxy**.

This repository is a complete, optimized C-language rewrite/port of the original Rust-based [cproxy](https://github.com/NOBLES5E/cproxy).

---

## Why C Rewrite?

While Rust is excellent for safety, writing low-level system software that interacts directly with kernel APIs (like `cgroups` and raw process states) can sometimes introduce unnecessary complexity and footprint overhead. The C implementation offers:

*   **Robust Privilege Dropping:** Safely elevates to root to set up rules, then flawlessly drops privileges back to the original user via `initgroups` and `getpwuid`. This perfectly restores the user's supplementary groups (such as `docker`) and environmental variables (`HOME`, `USER`), which is typically complex in Rust.
*   **Zero Dependencies:** Directly interacts with Linux system calls (libc, execvp, cgroup file I/O) without requiring any external libraries or heavy build tooling.
*   **Micro Footprint:** The compiled binary is usually **under 50KB**, making it suitable for resource-constrained systems (e.g., embedded routers, containers, thin clients).
*   **High Performance:** Sub-millisecond startup time and minimal runtime footprint.

---

## Features

| Feature | Description |
| :--- | :--- |
| **Redirect Mode** | Intercepts and redirects outbound TCP and DNS (UDP/TCP) traffic to a local port. |
| **TProxy Mode** | Transparently proxies TCP and UDP traffic with optional DNS override. |
| **Trace Mode** | Uses the `iptables LOG` target to audit and log application network activity in real time. |
| **Process Attaching** | Dynamically intercepts traffic of an already running process by target `PID`. |
| **Bypass Rules** | Bypasses specific IP ranges or CIDRs (e.g., LAN networks) to prevent routing loops. |
| **Dry-Run Mode** | Audits configuration and prints exact system commands without executing them. |
| **Garbage Collection** | Automatic stale cleanup option (`--clean`) to purge orphaned rules/cgroups from crashes. |

---

## Build and Install

You can compile `cproxy` using either the classic Makefile or CMake.

### Option 1: Classic Makefile (Default)
Suitable for quick builds without extra dependencies.
```bash
# Build
make

# Install (defaults to /usr/local/bin)
sudo make install
```

### Option 2: CMake (Recommended for IDEs and Packaging)
Suitable for modern developer environments and IDE integrations.
```bash
# Create build directory
mkdir build && cd build

# Configure and compile
cmake ..
make
```
*Note: In-tree builds (running `cmake .` in the root directory) are blocked to prevent overwriting the custom root Makefile.*

To uninstall:
```bash
sudo make uninstall
```

---

## Usage Guide

`cproxy` must be executed with root privileges (`sudo`) to modify system network rules and control groups.

### Core Commands

#### 1. Redirect Mode (TCP & DNS)
Spawn a command and redirect its TCP traffic and DNS queries to local proxy port `1080`:
```bash
sudo ./cproxy --mode redirect --port 1080 --redirect-dns -- <your-command>
```

#### 2. TProxy Mode (TCP & UDP)
Spawn a command and transparently proxy all TCP/UDP traffic with custom DNS destination:
```bash
sudo ./cproxy --mode tproxy --port 1080 --override-dns 1.1.1.1 -- <your-command>
```

#### 3. Bypass LAN IP Ranges
Avoid proxying local LAN ranges (supports comma-separated CIDR format):
```bash
sudo ./cproxy --mode tproxy --port 1080 --bypass "192.168.0.0/16,10.0.0.0/8" -- <your-command>
```

#### 4. Intercept an Existing Process
Take over the traffic of a process that is already running:
```bash
sudo ./cproxy --mode tproxy --port 1080 --pid <PID>
```

#### 5. Dry-Run Configuration Auditing
View the commands `cproxy` would run without executing them:
```bash
sudo ./cproxy --dry-run --mode tproxy --port 1080 -- <your-command>
```

#### 6. Garbage Collect Orphaned Rules
Clean up stale iptables rules and orphaned cgroups left behind by previous crashes:
```bash
sudo ./cproxy --clean
```

---

## Environment Preservation and `sudo -E`

Because `sudo` strips user environment paths for security, running commands that depend on local user settings (e.g., node scripts on `nvm`, user binary paths, etc.) might fail.

*   `cproxy` automatically restores basic variables (`HOME`, `USER`, `LOGNAME`) during privilege dropping.
*   For commands heavily dependent on the original user environment, run `cproxy` using the `sudo -E` option:
    ```bash
    sudo -E ./cproxy --mode redirect --port 1080 -- <your-command>
    ```

---

## IPv6 Handling
*   **Redirect Mode:** Outbound IPv6 traffic from the proxied process is **dropped** via the `raw` table to prevent traffic leaks, since IPv6 NAT redirection is complex and prone to security bypasses.
*   **TProxy/Trace Mode:** Full IPv6 support is implemented. Traffic is transparently routed or logged in the same manner as IPv4.

---

## Architecture

```
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

1.  **Isolation:** `cproxy` creates an isolated control group (`cproxy-<pid>`).
2.  **Privilege Separation:** The target process is spawned inside this cgroup after dropping root privileges back to the original user.
3.  **Interception:** `iptables` rules match packets tagged with the specific cgroup path (Cgroup v2) or Class ID (Cgroup v1) and redirect them to the designated proxy port.
4.  **Teardown:** When the target process exits or `cproxy` is interrupted, atexit hooks and signal handlers cleanly remove the cgroups and all associated `iptables` and routing table configurations.