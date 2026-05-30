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

# 4. Parsing test
# We can't easily test real functionality without being root and potentially messing with system state,
# but dry-run covers most of the logic.

echo "All basic tests passed!"
