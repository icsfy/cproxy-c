#!/usr/bin/env python3
import socket
import struct
import os
import sys

import threading

# Constants for socket options
SOL_IP = 0
IP_TRANSPARENT = 19
SO_ORIGINAL_DST = 80

def start_udp_server(port):
    """
    Starts a UDP server to test DNS redirection.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # For TProxy UDP, we might need IP_TRANSPARENT to bind to non-local IPs
        # but for simple REDIRECT to localhost, we don't strictly need it for binding to 0.0.0.0
        try:
            s.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
        except:
            pass
        s.bind(('0.0.0.0', port))
        print(f"UDP server listening on port {port}...")
        while True:
            data, addr = s.recvfrom(1024)
            print(f"Accepted UDP packet from {addr}, size {len(data)}")
            # Send a dummy response to acknowledge
            s.sendto(b"cproxy-dns-ok", addr)
    except Exception as e:
        print(f"UDP Server Error: {e}")

def start_tproxy(port):
    """
    Starts a TProxy server. Requires IP_TRANSPARENT and often root privileges.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
        except PermissionError:
            print("Error: IP_TRANSPARENT requires root privileges or CAP_NET_ADMIN.")
            sys.exit(1)

        s.bind(('0.0.0.0', port))
        s.listen(5)
        print(f"TProxy server listening on port {port}...")

        while True:
            conn, addr = s.accept()
            # In TProxy mode, getsockname() returns the original destination IP/port
            orig_dst = conn.getsockname()
            print(f"Accepted TProxy connection from {addr} to original destination {orig_dst}")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\ncproxy works!")
            conn.close()
    except KeyboardInterrupt:
        print("\nStopping TProxy server...")
    except Exception as e:
        print(f"Error: {e}")

def start_redirect(port):
    """
    Starts a REDIRECT mode server. Uses SO_ORIGINAL_DST to recover target.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(5)
        print(f"Redirect server listening on port {port}...")

        while True:
            conn, addr = s.accept()
            try:
                # Retrieve original destination address from iptables REDIRECT
                dst = conn.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
                srv_port, srv_ip = struct.unpack("!2xH4s8x", dst)
                orig_dst = (socket.inet_ntoa(srv_ip), srv_port)
                print(f"Accepted Redirect connection from {addr} to original destination {orig_dst}")
            except Exception as e:
                print(f"Accepted connection from {addr} (original destination unknown: {e})")

            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\ncproxy works!")
            conn.close()
    except KeyboardInterrupt:
        print("\nStopping Redirect server...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 test_proxy.py <mode> <port>")
        print("Modes: tproxy, redirect")
        sys.exit(1)

    mode = sys.argv[1].lower()
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Error: Port must be an integer.")
        sys.exit(1)

    # Start UDP server in a separate thread for DNS testing
    udp_thread = threading.Thread(target=start_udp_server, args=(port,), daemon=True)
    udp_thread.start()

    if mode == "tproxy":
        start_tproxy(port)
    elif mode == "redirect":
        start_redirect(port)
    else:
        print(f"Error: Unknown mode '{mode}'")
        sys.exit(1)
