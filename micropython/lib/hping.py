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

    # The checksum is calculated over the pseudo-header, the TCP header, and the payload.
    return checksum(pseudo_hdr + tcp_header + payload)

# --- Packet Sending Functions ---

def scan(host, ports="1-1024", timeout=1):
    """Performs a SYN scan on a range of ports for a given host."""
    print(f"Scanning {host} for open ports in range {ports}...")

    # Parse port range
    try:
        start_port, end_port = map(int, ports.split('-'))
    except ValueError:
        print("Invalid port range format. Use 'start-end' (e.g., '1-1024').")
        return

    for port in range(start_port, end_port + 1):
        flags = tcp(host, port, "S", timeout)

        # SYN-ACK is 0x12 (ACK=16, SYN=2)
        if flags is not None and (flags & 0x12):
            print(f"Port {port} is OPEN")
        # RST is 0x04 (RST=4)
        elif flags is not None and (flags & 0x04):
            # This means the port is closed
            pass
        else:
            # No response, filtered
            pass
    print("Scan complete.")


def udp(host, port, payload_str="hping-micropython"):
    """Sends a UDP packet to the specified host and port."""
    try:
        addr = socket.getaddrinfo(host, port)[0][-1]
    except IndexError:
        print(f"Could not resolve host: {host}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            payload = payload_str.encode()
            s.sendto(payload, addr)
            print(f"Sent {len(payload)} bytes to {host}:{port}")
        except Exception as e:
            print(f"An error occurred: {e}")

def tcp(host, port, flags_str="S", timeout=2):
    """Sends a raw TCP packet to the specified host and port."""
    # Resolve destination IP
    try:
        dst_ip = socket.getaddrinfo(host, port)[0][-1][0]
    except IndexError:
        # Silently fail for the scanner
        return None

    # Get local source IP
    wlan = network.WLAN(network.STA_IF)
    if not wlan.isconnected():
        # Silently fail for the scanner
        return None
    src_ip = wlan.ifconfig()[0]

    # --- Construct IP Header ---
    ip_ver_ihl = 0x45
    ip_tos = 0
    ip_len = 40
    ip_id = struct.unpack('!H', os.urandom(2))[0]
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_chk = 0
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ver_ihl, ip_tos, ip_len,
                             ip_id, ip_frag_off, ip_ttl, ip_proto,
                             ip_chk, ip_src, ip_dst)

    # --- Construct TCP Header ---
    src_port = 1024 + (struct.unpack('!H', os.urandom(2))[0] % (65535 - 1024))
    seq_num = struct.unpack('!I', os.urandom(4))[0]
    ack_num = 0
    data_off = (5 << 4)

    flags = 0
    if 'F' in flags_str.upper(): flags |= 1
    if 'S' in flags_str.upper(): flags |= 2
    if 'R' in flags_str.upper(): flags |= 4
    if 'P' in flags_str.upper(): flags |= 8
    if 'A' in flags_str.upper(): flags |= 16
    if 'U' in flags_str.upper(): flags |= 32

    window = 5840
    tcp_chk = 0
    urg_ptr = 0

    tcp_header_no_chk = struct.pack('!HHIIBBHHH', src_port, port, seq_num,
                                    ack_num, data_off, flags, window,
                                    tcp_chk, urg_ptr)

    payload = b''
    tcp_chk = tcp_checksum(src_ip, dst_ip, tcp_header_no_chk, payload)

    tcp_header = struct.pack('!HHIIBBHHH', src_port, port, seq_num,
                             ack_num, data_off, flags, window,
                             tcp_chk, urg_ptr)

    packet = ip_header + tcp_header

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (dst_ip, port))

            reply = s.recv(1024)

            reply_tcp_header = reply[20:40]

            r_src_port, r_dst_port, _, _, _, r_flags = struct.unpack('!HHIIBB', reply_tcp_header[:14])

            # Check if the reply is for our packet
            if r_dst_port == src_port:
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

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, 1) as s:
        s.settimeout(timeout)
        sequence_number = 0
        for _ in range(count):
            packet_id = os.urandom(2)
            payload = os.urandom(32)

            packet = struct.pack("!BBHHH", 8, 0, 0, struct.unpack("!H", packet_id)[0], sequence_number) + payload
            chk = checksum(packet)
            packet = struct.pack("!BBHHH", 8, 0, chk, struct.unpack("!H", packet_id)[0], sequence_number) + payload

            try:
                s.sendto(packet, (addr, 0))

                start_time = time.ticks_ms()
                reply = s.recv(1024)
                end_time = time.ticks_ms()

                ip_header = reply[0:20]
                icmp_header = reply[20:28]

                src_ip = ".".join(map(str, ip_header[12:16]))

                icmp_type, icmp_code, _, _, icmp_seq = struct.unpack("!BBHHH", icmp_header)

                if icmp_type == 0 and icmp_code == 0 and icmp_seq == sequence_number:
                    rtt = time.ticks_diff(end_time, start_time)
                    print(f"Reply from {src_ip}: bytes={len(reply) - 20}, time={rtt}ms, TTL={ip_header[8]}")
                else:
                    print("Received unexpected ICMP packet")

            except OSError as e:
                if e.args[0] == 110: # ETIMEDOUT
                    print(f"Request timed out.")
                else:
                    print(f"An error occurred: {e}")

            sequence_number += 1
            time.sleep(1)
