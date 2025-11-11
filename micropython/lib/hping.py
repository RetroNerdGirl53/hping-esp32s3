# hping.py
import socket
import time
import struct
import os

def checksum(packet):
    """Calculates the checksum of a packet."""
    if len(packet) % 2 != 0:
        packet += b'\0'

    s = 0
    for i in range(0, len(packet), 2):
        w = packet[i] + (packet[i+1] << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def ping(host, count=4, timeout=1):
    """Sends ICMP echo requests to the specified host."""
    try:
        addr = socket.getaddrinfo(host, 0)[0][-1][0]
    except IndexError:
        print(f"Could not resolve host: {host}")
        return

    print(f"Pinging {host} [{addr}] with 32 bytes of data:")

    # Create a raw socket
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.settimeout(timeout)
        sequence_number = 0
        for _ in range(count):
            # Construct the ICMP echo request packet
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
                print(f"Failed to send or receive packet: {e}")

            sequence_number += 1
            time.sleep(1)
