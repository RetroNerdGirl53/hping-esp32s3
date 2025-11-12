# hping.py
import socket
import time
import struct
import os
import network

# --- Checksum Functions ---

def checksum(packet):
    """Calculates the generic internet checksum of a packet."""
    if len(packet) % 2 != 0:
        packet += b'\0'

    s = 0
    for i in range(0, len(packet), 2):
        w = packet[i] + (packet[i+1] << 8)
        s += w

    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    s = ~s & 0xffff

    return s

def tcp_checksum(src_ip, dst_ip, tcp_header, payload):
    """Calculates the TCP checksum, including the pseudo-header."""
    pseudo_hdr = struct.pack('!4s4sBBH',
                             socket.inet_aton(src_ip),
                             socket.inet_aton(dst_ip),
                             0,
                             socket.IPPROTO_TCP,
                             len(tcp_header) + len(payload))

    return checksum(pseudo_hdr + tcp_header + payload)

# --- Packet Sending Functions ---

def traceroute(host, max_hops=30, timeout=2):
    """Performs a traceroute to the specified host."""
    try:
        dst_ip = socket.getaddrinfo(host, 0)[0][-1][0]
    except IndexError:
        print(f"Could not resolve host: {host}")
        return

    print(f"Traceroute to {host} ({dst_ip}), {max_hops} hops max")

    for ttl in range(1, max_hops + 1):
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.settimeout(timeout)

        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        port = 33434 + ttl
        send_socket.sendto(b'', (dst_ip, port))

        curr_addr = None
        start_time = time.ticks_ms()

        try:
            _, curr_addr = recv_socket.recvfrom(512)
            end_time = time.ticks_ms()
            curr_addr = curr_addr[0]

            rtt = time.ticks_diff(end_time, start_time)
            print(f"{ttl}\t{curr_addr}\t{rtt} ms")

        except socket.timeout:
            print(f"{ttl}\t*")

        finally:
            recv_socket.close()
            send_socket.close()

        if curr_addr == dst_ip:
            break

def scan(host, ports="1-1024", timeout=1):
    """Performs a SYN scan on a range of ports for a given host."""
    print(f"Scanning {host} for open ports in range {ports}...")

    try:
        start_port, end_port = map(int, ports.split('-'))
    except ValueError:
        print("Invalid port range format. Use 'start-end' (e.g., '1-1024').")
        return

    for port in range(start_port, end_port + 1):
        flags = tcp(host, port, "S", timeout=timeout)

        if flags is not None and (flags & 0x12):
            print(f"Port {port} is OPEN")
    print("Scan complete.")

def udp(host, port, payload_str="hping", sport=0):
    """Sends a UDP packet to the specified host and port."""
    try:
        addr = socket.getaddrinfo(host, port)[0][-1]
    except IndexError:
        print(f"Could not resolve host: {host}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        if sport != 0:
            s.bind(('', sport))
        try:
            payload = payload_str.encode()
            s.sendto(payload, addr)
            print(f"Sent {len(payload)} bytes from port {s.getsockname()[1]} to {host}:{port}")
        except Exception as e:
            print(f"An error occurred: {e}")

def tcp(host, port, flags_str="S", sport=0, payload_str="", timeout=2):
    """Sends a raw TCP packet to the specified host and port."""
    try:
        dst_ip = socket.getaddrinfo(host, port)[0][-1][0]
    except IndexError:
        return None

    wlan = network.WLAN(network.STA_IF)
    if not wlan.isconnected():
        return None
    src_ip = wlan.ifconfig()[0]

    payload = payload_str.encode()
    ip_len = 40 + len(payload)

    ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len,
                             struct.unpack('!H', os.urandom(2))[0], 0, 64,
                             socket.IPPROTO_TCP, 0, socket.inet_aton(src_ip),
                             socket.inet_aton(dst_ip))

    if sport == 0:
        sport = 1024 + (struct.unpack('!H', os.urandom(2))[0] % (65535 - 1024))

    seq_num = struct.unpack('!I', os.urandom(4))[0]

    flags = 0
    if 'F' in flags_str.upper(): flags |= 1
    if 'S' in flags_str.upper(): flags |= 2
    if 'R' in flags_str.upper(): flags |= 4
    if 'P' in flags_str.upper(): flags |= 8
    if 'A' in flags_str.upper(): flags |= 16
    if 'U' in flags_str.upper(): flags |= 32

    tcp_header_no_chk = struct.pack('!HHIIBBHHH', sport, port, seq_num, 0,
                                    (5 << 4), flags, 5840, 0, 0)

    tcp_chk = tcp_checksum(src_ip, dst_ip, tcp_header_no_chk, payload)
    tcp_header = struct.pack('!HHIIBBHHH', sport, port, seq_num, 0,
                             (5 << 4), flags, 5840, tcp_chk, 0)

    packet = ip_header + tcp_header + payload

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (dst_ip, port))
            reply = s.recv(1024)
            r_dst_port, _, _, _, _, r_flags = struct.unpack('!HHIIBB', reply[20:34])
            if r_dst_port == sport:
                return r_flags
        except OSError:
            return None

def ping(host, count=4, timeout=1):
    """Sends ICMP echo requests to the specified host."""
    try:
        addr = socket.getaddrinfo(host, 0)[0][-1][0]
    except IndexError:
        print(f"Could not resolve host: {host}")
        return

    print(f"Pinging {host} [{addr}] with 32 bytes of data:")

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.settimeout(timeout)
        for i in range(count):
            packet_id = os.urandom(2)
            packet = struct.pack("!BBHHH", 8, 0, 0, struct.unpack("!H", packet_id)[0], i) + os.urandom(32)
            chk = checksum(packet)
            packet = struct.pack("!BBHHH", 8, 0, chk, struct.unpack("!H", packet_id)[0], i) + os.urandom(32)

            try:
                s.sendto(packet, (addr, 0))
                start_time = time.ticks_ms()
                reply = s.recv(1024)
                end_time = time.ticks_ms()

                src_ip = ".".join(map(str, reply[12:16]))
                icmp_type, _, _, _, icmp_seq = struct.unpack("!BBHHH", reply[20:28])

                if icmp_type == 0 and icmp_seq == i:
                    rtt = time.ticks_diff(end_time, start_time)
                    print(f"Reply from {src_ip}: bytes=32, time={rtt}ms, TTL={reply[8]}")
                else:
                    print("Received unexpected ICMP packet")
            except OSError:
                print("Request timed out.")

            time.sleep(1)
