#!/usr/bin/env python3
import socket
import struct
import os
import sys
import threading
import time

# Constants for socket options
SOL_IP = 0
IP_TRANSPARENT = 19
SO_ORIGINAL_DST = 80
IP6T_SO_ORIGINAL_DST = 80

def build_dns_response(query_data):
    """
    Builds a simple DNS response. Points A queries to 1.2.3.4.
    Returns empty successful response for AAAA to avoid delays.
    """
    if len(query_data) < 12: return b""

    tx_id = query_data[:2]
    idx = 12
    while idx < len(query_data) and query_data[idx] != 0:
        idx += query_data[idx] + 1
    if idx + 5 > len(query_data): return b""

    qtype = struct.unpack("!H", query_data[idx+1:idx+3])[0]
    question_section = query_data[12:idx+5]

    if qtype == 1: # A Record
        flags = b"\x81\x80"
        counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"
        # Answer points to 1.2.3.4
        answer = b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x04" + b"\x01\x02\x03\x04"
        return tx_id + flags + counts + question_section + answer
    elif qtype == 28: # AAAA Record
        flags = b"\x81\x80"
        counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"
        # Answer points to ::ffff:1.2.3.4 (IPv4-mapped IPv6)
        answer = b"\xc0\x0c" + b"\x00\x1c\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x10" + \
                 b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x01\x02\x03\x04"
        return tx_id + flags + counts + question_section + answer
    else: # Others: return "No error, 0 answers"
        flags = b"\x81\x80"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        return tx_id + flags + counts + question_section

def start_udp_server(port):
    """
    Starts a UDP server to test DNS redirection.
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # IP_RECVORIGDSTADDR = 20, IPV6_RECVORIGDSTADDR = 74
            s.setsockopt(socket.SOL_IP, 20, 1)
            s.setsockopt(socket.IPPROTO_IPV6, 74, 1)
            s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
            s.setsockopt(socket.IPPROTO_IPV6, IP_TRANSPARENT, 1)
        except:
            pass
        s.bind(('::', port))
        print(f"UDP server listening on port {port} (DNS Mock)...")
        while True:
            # We need enough space for IPv6 address in ancdata
            data, ancdata, msg_flags, addr = s.recvmsg(1024, socket.CMSG_SPACE(128))

            orig_dst = None
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                if (cmsg_level == socket.SOL_IP and cmsg_type == 20):
                    # IPv4: family(2), port(2), addr(4), padding(8)
                    family, p, ip_raw = struct.unpack("!HH4s8x", cmsg_data)
                    orig_dst = (socket.inet_ntoa(ip_raw), p)
                elif (cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == 74):
                    # IPv6: family(2), port(2), flowinfo(4), addr(16), scope_id(4)
                    family, p, flowinfo, ip_raw, scope_id = struct.unpack("!HH I 16s I", cmsg_data)
                    orig_dst = (socket.inet_ntop(socket.AF_INET6, ip_raw), p)

            print(f"Accepted DNS query from {addr}, original destination {orig_dst}")
            response = build_dns_response(data)
            if not response: continue

            if orig_dst:
                try:
                    # Spoof source address
                    is_ipv6 = ":" in orig_dst[0]
                    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET

                    target_addr = addr
                    if not is_ipv6 and len(addr) == 4:
                        # Convert IPv6-mapped IPv4 to 2-tuple for AF_INET socket
                        host = addr[0]
                        if host.startswith("::ffff:"):
                            host = host[7:]
                        target_addr = (host, addr[1])
                    elif is_ipv6 and len(addr) == 2:
                        # Convert 2-tuple to 4-tuple for AF_INET6 socket (unlikely here but for completeness)
                        target_addr = (addr[0], addr[1], 0, 0)

                    resp_s = socket.socket(family, socket.SOCK_DGRAM)
                    resp_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if family == socket.AF_INET:
                        resp_s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                    else:
                        resp_s.setsockopt(socket.IPPROTO_IPV6, IP_TRANSPARENT, 1)
                    resp_s.bind(orig_dst)
                    resp_s.sendto(response, target_addr)
                    resp_s.close()
                    continue
                except Exception as e:
                    print(f"Spoofing failed: {e}")

            s.sendto(response, addr)
    except Exception as e:
        print(f"UDP Server Error: {e}")

def start_tproxy(port):
    """
    Starts a TProxy server for IPv4 and IPv6.
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
            s.setsockopt(socket.IPPROTO_IPV6, IP_TRANSPARENT, 1)
        except PermissionError:
            print("Error: IP_TRANSPARENT requires root privileges or CAP_NET_ADMIN.")
            sys.exit(1)

        s.bind(('::', port))
        s.listen(5)
        print(f"TProxy server listening on port {port}...")

        while True:
            conn, addr = s.accept()
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
    Starts a REDIRECT mode server.
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
                # IPv4
                dst = conn.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
                srv_port, srv_ip = struct.unpack("!2xH4s8x", dst)
                orig_dst = (socket.inet_ntoa(srv_ip), srv_port)
                print(f"Accepted Redirect connection from {addr} to original destination {orig_dst}")
            except Exception as e:
                print(f"Accepted connection from {addr} (original destination unknown)")

            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\ncproxy works!")
            conn.close()
    except KeyboardInterrupt:
        print("\nStopping Redirect server...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 test_proxy.py <mode> <port>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    port = int(sys.argv[2])

    udp_thread = threading.Thread(target=start_udp_server, args=(port,), daemon=True)
    udp_thread.start()

    if mode == "tproxy":
        start_tproxy(port)
    elif mode == "redirect":
        start_redirect(port)
    else:
        print(f"Error: Unknown mode '{mode}'")
        sys.exit(1)
