#!/bin/bash

# Configuration
PROXY_PORT=1080
TEST_URL="http://1.1.1.1" # Using an IP to avoid DNS issues in basic test

# Colors
GREEN='\033[0-32m'
RED='\033[0-31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

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
    sudo python3 -u test_proxy.py "$mode" $PROXY_PORT > proxy.log 2>&1 &
    PROXY_PID=$!

    # Wait for proxy to start
    sleep 2

    # Run cproxy and capture output of curl
    # We use --bypass to ensure we don't proxy the proxy's own traffic (though cgroups)
    OUTPUT=$(sudo ./cproxy --mode "$mode" --port $PROXY_PORT -- curl -s -m 5 $TEST_URL)

    if [[ "$OUTPUT" == *"cproxy works!"* ]]; then
        log_info "PASS: $mode mode TCP works correctly"
    else
        log_error "FAIL: $mode mode TCP failed"
        echo "Output was: $OUTPUT"
        echo "Proxy log:"
        cat proxy.log
        exit 1
    fi

    # DNS Test
    log_info "Testing DNS redirection in $mode mode..."
    local dns_flag=""
    if [[ "$mode" == "redirect" ]]; then
        dns_flag="--redirect-dns"
    fi

    # Use nc to send a UDP packet to 8.8.8.8:53 and see if it's intercepted
    # We expect our proxy log to show "Accepted UDP packet"
    sudo ./cproxy --mode "$mode" --port $PROXY_PORT $dns_flag -- bash -c "echo 'dns-test' | nc -u -w 2 8.8.8.8 53" > /dev/null 2>&1

    if grep -q "Accepted UDP packet" proxy.log; then
        log_info "PASS: $mode mode DNS works correctly"
    else
        log_error "FAIL: $mode mode DNS failed"
        echo "Proxy log:"
        cat proxy.log
        exit 1
    fi


    # Kill proxy for next test
    sudo kill $PROXY_PID 2>/dev/null
    wait $PROXY_PID 2>/dev/null
    PROXY_PID=""
    sudo ./cproxy --clean > /dev/null 2>&1
    sleep 1
}

# Build first
make clean && make

# Run tests
run_test "redirect"
run_test "tproxy"

log_info "All end-to-end tests passed successfully!"
