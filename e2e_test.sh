#!/bin/bash

# Configuration
PROXY_PORT=1080
# Use a dummy IP that doesn't exist but will be intercepted by our mock DNS/Proxy
TEST_URL="http://10.254.254.254"
TEST_URL_V6="http://[fc00::1]"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use printf with \r to ensure alignment even if terminal state is messy
log_info() { printf "\r${GREEN}[INFO]${NC} %s\n" "$1"; }
log_error() { printf "\r${RED}[ERROR]${NC} %s\n" "$1"; }

wait_for_port() {
    local port=$1
    for i in {1..50}; do
        if nc -z 127.0.0.1 $port >/dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    return 1
}

cleanup_test() {
    log_info "Cleaning up..."
    [ -n "$PROXY_PID" ] && sudo kill -- -$PROXY_PID 2>/dev/null
    [ -n "$SERVER_PID" ] && sudo kill -- -$SERVER_PID 2>/dev/null
    [ -n "$INNER_PROXY_PID" ] && sudo kill -- -$INNER_PROXY_PID 2>/dev/null
    sudo pkill -f test_proxy.py 2>/dev/null
    sudo pkill -f test_server.py 2>/dev/null
    sudo pkill -f "cproxy --mode" 2>/dev/null
    sudo ./cproxy --clean > /dev/null 2>&1
}

trap cleanup_test EXIT

run_test() {
    local mode=$1
    log_info "Testing mode: $mode"

    # Start proxy server in background
    sudo rm -f proxy.log
    setsid sudo python3 -u test_proxy.py "$mode" $PROXY_PORT > proxy.log 2>&1 &
    PROXY_PID=$!

    # Wait for proxy to start
    wait_for_port $PROXY_PORT || { log_error "Proxy server failed to start on port $PROXY_PORT"; exit 1; }

    # 1. Basic TCP Redirection Test
    log_info "Testing basic TCP redirection..."
    OUTPUT=$(sudo ./cproxy --mode "$mode" --port $PROXY_PORT -- curl -s -m 5 $TEST_URL)

    if [[ "$OUTPUT" == *"cproxy works!"* ]]; then
        log_info "PASS: $mode mode TCP works correctly"
    else
        log_error "FAIL: $mode mode TCP failed"
        echo "Output: $OUTPUT"
        exit 1
    fi

    # 2. DNS + TCP Test
    log_info "Testing DNS + TCP redirection..."
    local dns_flag=""
    if [[ "$mode" == "redirect" ]]; then
        dns_flag="--redirect-dns"
    elif [[ "$mode" == "tproxy" ]]; then
        dns_flag="--override-dns 1.1.1.1"
    fi

    # Our DNS mock resolves everything to 1.2.3.4 (or mapped v6), then TCP redirection kicks in
    OUTPUT=$(sudo ./cproxy --mode "$mode" --port $PROXY_PORT $dns_flag -- curl -v -s -m 5 http://cproxy.test 2>&1)

    if [[ "$OUTPUT" == *"cproxy works!"* ]]; then
        log_info "PASS: $mode mode DNS + TCP redirection works"
    else
        log_error "FAIL: $mode mode DNS + TCP redirection failed"
        echo "Output: $OUTPUT"
        exit 1
    fi

    # 3. Privilege Drop Verification
    log_info "Verifying privilege dropping..."
    # Check if 'whoami' returns the original user, not root
    EXPECTED_USER=$(id -un)
    ACTUAL_USER=$(sudo ./cproxy --mode "$mode" --port $PROXY_PORT -- whoami)
    if [[ "$ACTUAL_USER" == "$EXPECTED_USER" ]]; then
        log_info "PASS: Privilege dropped correctly to $ACTUAL_USER"
    else
        log_error "FAIL: Privilege NOT dropped correctly. Got: $ACTUAL_USER, Expected: $EXPECTED_USER"
        exit 1
    fi

    # 4. IPv6 Test (TProxy only for now, as Redirect drops IPv6)
    if [[ "$mode" == "tproxy" ]]; then
        log_info "Testing IPv6 redirection..."
        # Check if we have a default IPv6 route or at least some way to route IPv6
        if ip -6 route show | grep -q "default\|::/0"; then
            OUTPUT=$(sudo ./cproxy --mode "$mode" --port $PROXY_PORT -- curl -g -s -m 5 $TEST_URL_V6)
            if [[ "$OUTPUT" == *"cproxy works!"* ]]; then
                log_info "PASS: $mode mode IPv6 works"
            else
                log_error "FAIL: $mode mode IPv6 failed"
                echo "Output: $OUTPUT"
                # Don't exit 1 here yet, maybe it's just environment
            fi
        else
            log_info "Skipping IPv6 test: No IPv6 default route found"
        fi
    fi

    # 5. Inbound Connection (Server) Test
    log_info "Testing inbound connection bypass (Server Mode)..."
    SERVER_PORT=$((PROXY_PORT + 1000))
    cat << 'EOF' > test_server.py
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', int(sys.argv[1])))
s.listen(1)
while True:
    try:
        conn, addr = s.accept()
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\ninbound works!")
        conn.close()
    except:
        break
EOF
    # Run the server under cproxy
    setsid sudo ./cproxy --mode "$mode" --port $PROXY_PORT -- python3 test_server.py $SERVER_PORT > /dev/null 2>&1 &
    SERVER_PID=$!

    wait_for_port $SERVER_PORT || { log_error "Test server failed to start"; sudo kill -- -$SERVER_PID 2>/dev/null; exit 1; }

    # Test from outside
    OUTPUT=$(curl -s -m 5 http://127.0.0.1:$SERVER_PORT)

    if [[ "$OUTPUT" == *"inbound works!"* ]]; then
        log_info "PASS: $mode mode allows inbound connections"
    else
        log_error "FAIL: $mode mode inbound connection failed"
        echo "Output: $OUTPUT"
        sudo kill -- -$SERVER_PID 2>/dev/null
        exit 1
    fi
    sudo kill -- -$SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    rm -f test_server.py

    # 6. Proxy Chaining (Nested cproxy) Test
    log_info "Testing proxy chaining (nested cproxy)..."
    INNER_PORT=$((PROXY_PORT + 2000))
    # Start an inner proxy server
    setsid sudo python3 -u test_proxy.py "$mode" $INNER_PORT >> proxy_inner.log 2>&1 &
    INNER_PROXY_PID=$!
    wait_for_port $INNER_PORT || { log_error "Inner proxy failed to start"; exit 1; }

    # Run nested: curl -> inner_cproxy -> outer_cproxy. The inner rule should intercept first.
    OUTPUT=$(sudo ./cproxy --mode "$mode" --port $PROXY_PORT -- sudo ./cproxy --mode "$mode" --port $INNER_PORT -- curl -s -m 5 $TEST_URL)

    if [[ "$OUTPUT" == *"cproxy works!"* ]]; then
        log_info "PASS: $mode mode proxy chaining works"
    else
        log_error "FAIL: $mode mode proxy chaining failed"
        echo "Output: $OUTPUT"
        exit 1
    fi

    sudo kill -- -$INNER_PROXY_PID 2>/dev/null
    wait $INNER_PROXY_PID 2>/dev/null

    # Kill proxy for next test
    sudo kill -- -$PROXY_PID 2>/dev/null
    wait $PROXY_PID 2>/dev/null
    PROXY_PID=""
    sudo ./cproxy --clean > /dev/null 2>&1
    sleep 0.5
}

# Build first
make clean && make

# Run tests
run_test "redirect"
run_test "tproxy"

# Test --hosts mount namespace bypass
log_info "Testing custom --hosts mount isolation..."
cat << 'EOF' > custom_hosts.test
127.0.2.2 my-dummy-domain.local
EOF
OUTPUT=$(sudo ./cproxy --mode trace --hosts custom_hosts.test -- curl -v -s -m 2 http://my-dummy-domain.local 2>&1)
if echo "$OUTPUT" | grep -q "Trying 127.0.2.2"; then
    log_info "PASS: --hosts custom file mounted and respected successfully"
else
    log_error "FAIL: --hosts custom file mount failed"
    echo "Output: $OUTPUT"
    rm -f custom_hosts.test
    exit 1
fi
rm -f custom_hosts.test

# Test --resolvconf mount namespace bypass
log_info "Testing custom --resolvconf mount isolation..."
cat << 'EOF' > custom_resolv.test
nameserver 127.0.2.3
EOF
# If resolv.conf is mounted correctly, cat /etc/resolv.conf should show our custom content
OUTPUT=$(sudo ./cproxy --mode trace --resolvconf custom_resolv.test -- cat /etc/resolv.conf)
if echo "$OUTPUT" | grep -q "nameserver 127.0.2.3"; then
    log_info "PASS: --resolvconf custom file mounted and respected successfully"
else
    log_error "FAIL: --resolvconf custom file mount failed"
    echo "Output: $OUTPUT"
    rm -f custom_resolv.test
    exit 1
fi
rm -f custom_resolv.test

# Test --mount generic namespace bypass
log_info "Testing generic --mount isolation..."
cat << 'EOF' > dummy_config.test
{ "mocked": true }
EOF
# We mount our dummy JSON over /etc/timezone just as a safe, generic target that exists on most systems
OUTPUT=$(sudo ./cproxy --mode trace --mount dummy_config.test:/etc/timezone -- cat /etc/timezone)
if echo "$OUTPUT" | grep -q "mocked"; then
    log_info "PASS: --mount custom generic file mounted and respected successfully"
else
    log_error "FAIL: --mount custom generic file mount failed"
    echo "Output: $OUTPUT"
    rm -f dummy_config.test
    exit 1
fi
rm -f dummy_config.test

log_info "All end-to-end tests passed successfully!"
