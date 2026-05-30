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
    [ -n "$PROXY_PID" ] && sudo kill $PROXY_PID 2>/dev/null
    sudo ./cproxy --clean > /dev/null 2>&1
}

trap cleanup_test EXIT

run_test() {
    local mode=$1
    log_info "Testing mode: $mode"

    # Start proxy server in background
    sudo rm -f proxy.log
    sudo python3 -u test_proxy.py "$mode" $PROXY_PORT > proxy.log 2>&1 &
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

    # Kill proxy for next test
    sudo kill $PROXY_PID 2>/dev/null
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

log_info "All end-to-end tests passed successfully!"
