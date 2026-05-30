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
    Supports transparent responses by spoofing original destination.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # IP_RECVORIGDSTADDR = 20
        try:
            s.setsockopt(socket.SOL_IP, 20, 1)
            s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        except:
            pass
        s.bind(('0.0.0.0', port))
        print(f"UDP server listening on port {port}...")
        while True:
            # Use recvmsg to get ancillary data (original destination)
            data, ancdata, msg_flags, addr = s.recvmsg(1024, socket.CMSG_SPACE(24))
            
            orig_dst = None
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                if cmsg_level == socket.SOL_IP and cmsg_type == 20: # IP_ORIGDSTADDR
                    # sockaddr_in is 16 bytes: family(2), port(2), addr(4), zero(8)
                    family, port_raw, ip_raw = struct.unpack("!HH4s8x", cmsg_data)
                    orig_dst = (socket.inet_ntoa(ip_raw), port_raw)
            
            print(f"Accepted UDP packet from {addr}, size {len(data)}")
            
            response = b"cproxy-dns-ok"
            if orig_dst:
                # Transparent response: spoof source as original destination
                try:
                    resp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    resp_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    resp_s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                    resp_s.bind(orig_dst)
                    resp_s.sendto(response, addr)
                    resp_s.close()
                    continue
                except Exception as e:
                    print(f"Failed to send transparent response: {e}")
            
            # Fallback for standard REDIRECT (NAT handles it)
            s.sendto(response, addr)
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
