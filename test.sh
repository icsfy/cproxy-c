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

# 9. Verify sudo / privilege elevation works under setuid cproxy
sudo chown root:root cproxy && sudo chmod 4755 cproxy
OUTPUT=$(./cproxy --mode redirect --port 1080 -- sudo whoami 2>&1)
if [[ "$OUTPUT" == *"root"* ]]; then
    echo "[PASS] sudo works correctly under setuid cproxy"
else
    echo "[FAIL] sudo failed under cproxy: $OUTPUT"
    exit 1
fi

# 10. IPv4-only and IPv6-only dry run tests
sudo ./cproxy -D -4 --mode tproxy --port 1080 -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] -4/--ipv4-only works in dry run (tproxy)"
else
    echo "[FAIL] -4/--ipv4-only failed in dry run (tproxy)"
    exit 1
fi

sudo ./cproxy -D -6 --mode tproxy --port 1080 -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] -6/--ipv6-only works in dry run (tproxy)"
else
    echo "[FAIL] -6/--ipv6-only failed in dry run (tproxy)"
    exit 1
fi

sudo ./cproxy -D -4 --mode redirect --port 1080 -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] -4/--ipv4-only works in dry run (redirect)"
else
    echo "[FAIL] -4/--ipv4-only failed in dry run (redirect)"
    exit 1
fi

sudo ./cproxy -D -6 --mode redirect --port 1080 -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] -6/--ipv6-only works in dry run (redirect)"
else
    echo "[FAIL] -6/--ipv6-only failed in dry run (redirect)"
    exit 1
fi

# 11. Conflict between -4 and -6
./cproxy -4 -6 -- ls > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] Simultaneous -4 and -6 rejected"
else
    echo "[FAIL] Simultaneous -4 and -6 accepted"
    exit 1
fi

# 12. DNS override family validation
./cproxy -4 -o 2001:db8::1 -- ls > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] IPv6 DNS override rejected with -4"
else
    echo "[FAIL] IPv6 DNS override accepted with -4"
    exit 1
fi

./cproxy -6 -o 1.1.1.1 -- ls > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] IPv4 DNS override rejected with -6"
else
    echo "[FAIL] IPv4 DNS override accepted with -6"
    exit 1
fi

# 13. Direct mode and --no-proxy tests
sudo ./cproxy -D --mode direct -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] --mode direct works in dry run"
else
    echo "[FAIL] --mode direct failed in dry run"
    exit 1
fi

sudo ./cproxy -D --no-proxy -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] --no-proxy works in dry run"
else
    echo "[FAIL] --no-proxy failed in dry run"
    exit 1
fi

sudo ./cproxy -D --mode direct -4 -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] --mode direct -4 works in dry run"
else
    echo "[FAIL] --mode direct -4 failed in dry run"
    exit 1
fi

sudo ./cproxy -D --mode direct -6 -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] --mode direct -6 works in dry run"
else
    echo "[FAIL] --mode direct -6 failed in dry run"
    exit 1
fi

sudo ./cproxy -D --mode direct -o 1.1.1.1 -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] --mode direct with --override-dns works in dry run"
else
    echo "[FAIL] --mode direct with --override-dns failed in dry run"
    exit 1
fi

# 14. Direct mode live CPROXY_ENV verification
OUTPUT=$(sudo ./cproxy --mode direct -- sh -c 'echo $CPROXY_ENV')
if [ "$OUTPUT" = "cproxy/direct" ]; then
    echo "[PASS] CPROXY_ENV is set to cproxy/direct in direct mode"
else
    echo "[FAIL] Unexpected CPROXY_ENV in direct mode: $OUTPUT"
    exit 1
fi

# 15. Invalid --env format rejection
./cproxy -e INVALID_FORMAT -- ls > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] Invalid --env format without '=' rejected"
else
    echo "[FAIL] Invalid --env format without '=' was accepted"
    exit 1
fi

./cproxy -e =EMPTY_KEY -- ls > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] Invalid --env format with empty key rejected"
else
    echo "[FAIL] Invalid --env format with empty key was accepted"
    exit 1
fi

# 16. Conflict between --redirect-dns and --override-dns
./cproxy -d -o 1.1.1.1 -- ls > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[PASS] Simultaneous --redirect-dns and --override-dns rejected"
else
    echo "[FAIL] Simultaneous --redirect-dns and --override-dns was accepted"
    exit 1
fi

# 17. Redirect mode with --override-dns in dry run
sudo ./cproxy -D --mode redirect --override-dns 1.1.1.1 -- ls > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[PASS] --mode redirect with --override-dns works in dry run"
else
    echo "[FAIL] --mode redirect with --override-dns failed in dry run"
    exit 1
fi

# 18. --help writes to stdout (not stderr)
HELP_STDERR=$(./cproxy --help 2>&1 > /dev/null)
if [ -z "$HELP_STDERR" ]; then
    echo "[PASS] --help writes cleanly to stdout"
else
    echo "[FAIL] --help wrote to stderr: $HELP_STDERR"
    exit 1
fi

echo "All basic tests passed!"
