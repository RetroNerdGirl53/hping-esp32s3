# hping.py
import wifi
import ipaddress
import adafruit_logging as logging
import socketpool
import time
import struct
import os

# Set up logging
logger = logging.getLogger(__name__)

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
    pool = socketpool.SocketPool(wifi.radio)
    try:
        addr = pool.getaddrinfo(host, 0)[0][4][0]
    except IndexError:
        logger.error(f"Could not resolve host: {host}")
        return

    logger.info(f"Pinging {host} [{addr}] with 32 bytes of data:")

    # Create a raw socket
    # The second argument is the protocol number, which is 1 for ICMP.
    # See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    with pool.socket(socketpool.AF_INET, socketpool.SOCK_RAW, 1) as s:
        s.settimeout(timeout)
        sequence_number = 0
        for _ in range(count):
            # Construct the ICMP echo request packet
            # Type (8) + Code (0) + Checksum (0) + ID + Sequence Number
            # The ID is a random number.
            packet_id = os.urandom(2)

            # The payload is 32 bytes of random data.
            payload = os.urandom(32)

            # The checksum is calculated over the ICMP message.
            # First, we create a packet with a checksum of 0.
            packet = struct.pack("!BBHHH", 8, 0, 0, struct.unpack("!H", packet_id)[0], sequence_number) + payload

            # Then, we calculate the checksum.
            chk = checksum(packet)

            # Finally, we create the real packet with the correct checksum.
            packet = struct.pack("!BBHHH", 8, 0, chk, struct.unpack("!H", packet_id)[0], sequence_number) + payload

            try:
                s.sendto(packet, (addr, 0))

                # Wait for the reply
                start_time = time.monotonic()
                reply = s.recv(1024)
                end_time = time.monotonic()

                # The ICMP reply is a bit more complex to parse.
                # The first 20 bytes are the IP header.
                ip_header = reply[0:20]

                # The next 8 bytes are the ICMP header.
                icmp_header = reply[20:28]

                # Unpack the IP header to get the source IP address
                # The source IP address is at offset 12
                src_ip = ".".join(map(str, ip_header[12:16]))

                # Unpack the ICMP header to get the type, code, and sequence number
                icmp_type, icmp_code, _, _, icmp_seq = struct.unpack("!BBHHH", icmp_header)

                if icmp_type == 0 and icmp_code == 0 and icmp_seq == sequence_number:
                    rtt = (end_time - start_time) * 1000
                    logger.info(f"Reply from {src_ip}: bytes={len(reply) - 20}, time={rtt:.2f}ms, TTL={ip_header[8]}")
                else:
                    logger.warning("Received unexpected ICMP packet")

            except OSError as e:
                logger.error(f"Failed to send or receive packet: {e}")

            sequence_number += 1
            time.sleep(1)
