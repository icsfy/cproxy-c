#!/bin/bash
# Simple test script for cproxy

# Check if built
if [ ! -f ./cproxy ]; then
    echo "cproxy not found, building..."
    make
fi

# 1. Check help output
./cproxy --help > /dev/null
if [ $? -eq 0 ]; then
    echo "[PASS] --help works"
else
    echo "[FAIL] --help failed"
    exit 1
fi

# 2. Check version output
./cproxy --version | grep -q "cproxy version"
if [ $? -eq 0 ]; then
    echo "[PASS] --version works"
else
    echo "[FAIL] --version failed"
    exit 1
fi

# 3. Dry-run test
sudo ./cproxy --dry-run --mode tproxy --port 1080 --bypass 1.1.1.1 -- ls > /dev/null
if [ $? -eq 0 ]; then
    echo "[PASS] --dry-run works"
else
    echo "[FAIL] --dry-run failed"
    exit 1
fi

# 4. Parsing test with --hosts, --resolvconf, --user, --env, and --mount
sudo ./cproxy --dry-run --mode redirect --port 1080 --hosts /dev/null --resolvconf /dev/null -u nobody -e TEST=1 -M /dev/null:/etc/machine-id -- ls > /dev/null
if [ $? -eq 0 ]; then
    echo "[PASS] Extra feature flags work"
else
    echo "[FAIL] Extra feature flags failed"
    exit 1
fi

# 5. Exit code propagation test
sudo ./cproxy --mode redirect --port 1080 -- /non_existent_binary_xyz_12345 > /dev/null 2>&1
STATUS=$?
if [ $STATUS -eq 127 ]; then
    echo "[PASS] Command not found returns 127"
else
    echo "[FAIL] Expected exit code 127 for command not found, got $STATUS"
    exit 1
fi

sudo ./cproxy --mode redirect --port 1080 -- ./Makefile > /dev/null 2>&1
STATUS=$?
if [ $STATUS -eq 126 ]; then
    echo "[PASS] Non-executable command returns 126"
else
    echo "[FAIL] Expected exit code 126 for non-executable file, got $STATUS"
    exit 1
fi

# 6. SetUID security check (--mount rejected when non-root)
./cproxy -M /dev/null:/tmp/test_cproxy -- ls > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] --mount rejected for non-root user"
else
    echo "[FAIL] --mount was allowed for non-root user"
    exit 1
fi

# 7. Invalid PID check
sudo ./cproxy -i 9999999 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] Non-existent PID rejected"
else
    echo "[FAIL] Non-existent PID was accepted"
    exit 1
fi

# 8. Conflict between --pid and command
sudo ./cproxy -i $$ -- ls > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] Simultaneous --pid and command rejected"
else
    echo "[FAIL] Simultaneous --pid and command was accepted"
    exit 1
fi

# We can't easily test real functionality without being root and potentially messing with system state,
# but dry-run covers most of the logic.

echo "All basic tests passed!"
