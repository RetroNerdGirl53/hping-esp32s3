# hping.py
import socket
import time
import struct
import os
import network

# --- Utility Functions ---

def dump_packet(packet):
    """Prints a hex dump of a packet."""
    for i, byte in enumerate(packet):
        if i % 16 == 0:
            print(f"\n{i:04x}  ", end="")
        print(f"{byte:02x} ", end="")
    print("\n")

def checksum(packet):
    """Calculates the generic internet checksum."""
    if len(packet) % 2 != 0: packet += b'\0'
    s = sum(packet[i] + (packet[i+1] << 8) for i in range(0, len(packet), 2))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def _create_pseudo_header(src_ip, dst_ip, protocol, length):
    """Creates a TCP/UDP pseudo-header for checksum calculation."""
    return struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, protocol, length)

# --- Header Creation ---

def _create_ip_header(src_ip, dst_ip, protocol, packet_len, ttl):
    """Creates a standard IP header with a calculated checksum."""
    ip_header_no_chk = struct.pack('!BBHHHBBH4s4s', 0x45, 0, packet_len,
                                 struct.unpack('!H', os.urandom(2))[0], 0,
                                 ttl, protocol, 0,
                                 socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = checksum(ip_header_no_chk)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, packet_len,
                         struct.unpack('!H', os.urandom(2))[0], 0,
                         ttl, protocol, ip_chk,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

# --- Core Logic ---

def send_packets(sock, packet, dst_ip, port, count, interval, quiet, verbose, keep=False, sport=0):
    """Sends packets and handles output based on verbosity."""
    for i in range(count):
        try:
            sock.sendto(packet, (dst_ip, port))
            if not quiet and interval > 0 and count > 1:
                print(f"Packet {i+1} sent.")
            if interval > 0:
                time.sleep_ms(interval)
        except Exception as e:
            if not quiet: print(f"Error sending packet: {e}")
            break
    if not quiet and (count > 1 or interval == 0):
        print(f"Sent {count} packets.")

def _handle_reply(sock, dst_ip, verbose):
    """Receives a packet and handles verbose output."""
    try:
        reply, addr = sock.recvfrom(1024)

        if addr[0] == dst_ip:
            if verbose:
                print(f"len={len(reply)} ip={addr[0]} ttl={reply[8]}")
                dump_packet(reply)
            return reply
        return None
    except OSError:
        return None

# --- Public Commands ---

def discover(timeout=1):
    """Discovers live hosts on the local network using a ping sweep."""
    wlan = network.WLAN(network.STA_IF)
    if not wlan.isconnected():
        print("WiFi is not connected. Please connect first.")
        return

    ip_info = wlan.ifconfig()
    my_ip, subnet_mask, gateway, _ = ip_info

    my_ip_int = int.from_bytes(socket.inet_aton(my_ip), 'big')
    subnet_int = int.from_bytes(socket.inet_aton(subnet_mask), 'big')
    network_addr_int = my_ip_int & subnet_int
    broadcast_addr_int = network_addr_int | (~subnet_int & 0xFFFFFFFF)

    start_ip_int = network_addr_int + 1
    end_ip_int = broadcast_addr_int - 1

    print(f"Starting network discovery for {socket.inet_ntoa(network_addr_int.to_bytes(4, 'big'))}...")
    live_hosts = []

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.settimeout(timeout)
        for i in range(start_ip_int, end_ip_int + 1):
            dst_ip = socket.inet_ntoa(i.to_bytes(4, 'big'))
            print(f"Pinging {dst_ip}...")

            packet_id = os.urandom(2)
            packet = struct.pack("!BBHHH", 8, 0, 0, struct.unpack("!H", packet_id)[0], 0)
            packet = struct.pack("!BBHHH", 8, 0, checksum(packet), struct.unpack("!H", packet_id)[0], 0)

            try:
                s.sendto(packet, (dst_ip, 0))
                reply, addr = s.recvfrom(64)
                if addr[0] == dst_ip:
                    print(f"  -> Host {dst_ip} is live.")
                    live_hosts.append(dst_ip)
            except OSError:
                pass

    print("\nDiscovery complete. Live hosts found:")
    for host in live_hosts:
        print(host)

def profile(host, timeout=1):
    """Scans common ports to make an educated guess about the host's role."""
    print(f"Profiling host {host}...")

    wlan = network.WLAN(network.STA_IF)
    if wlan.isconnected() and host == wlan.ifconfig()[2]:
        print(f"  -> This host is the network's Default Gateway (Router).")

    common_ports = {
        22: "SSH (Linux/macOS/Server)",
        80: "HTTP (Web Server)",
        443: "HTTPS (Secure Web Server)",
        139: "NetBIOS (Windows File Sharing)",
        445: "SMB (Windows File Sharing)"
    }

    open_ports = []
    for port, service in common_ports.items():
        print(f"Checking port {port}...")
        flags = tcp(host, port, "S", timeout=timeout, scanner=True)
        if flags is not None and (flags & 0x12):
            open_ports.append((port, service))

    if open_ports:
        print("\nEducated Guess:")
        for port, service in open_ports:
            print(f"  -> Port {port} is open, suggesting it may be a {service}.")
    else:
        print("\nCould not identify any common services on this host.")

def ping(host, count=4, interval=1000, ttl=64, spoof_ip=None, verbose=False, quiet=False, data_size=0):
    """Sends ICMP echo requests."""
    try:
        dst_ip = socket.getaddrinfo(host, 0)[0][-1][0]
    except (IndexError, OSError) as e:
        if not quiet: print(f"Error resolving host: {e}")
        return

    if not quiet: print(f"Pinging {host} ({dst_ip})")

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.settimeout(2)
        s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        for i in range(count):
            packet_id = os.urandom(2)
            payload = os.urandom(data_size) if data_size > 0 else b''
            icmp_header_no_chk = struct.pack("!BBHHH", 8, 0, 0, struct.unpack('!H', packet_id)[0], i) + payload
            chk = checksum(icmp_header_no_chk)
            packet = struct.pack("!BBHHH", 8, 0, chk, struct.unpack('!H', packet_id)[0], i) + payload

            try:
                s.sendto(packet, (dst_ip, 0))
                start_time = time.ticks_ms()
                reply = _handle_reply(s, dst_ip, verbose)
                end_time = time.ticks_ms()
                if reply and not quiet:
                    rtt = time.ticks_diff(end_time, start_time)
                    print(f"Reply from {dst_ip}: bytes={len(reply)}, time={rtt}ms")
                elif not reply and not quiet:
                    print("Request timed out.")

                if interval > 0: time.sleep_ms(interval)
            except Exception as e:
                if not quiet: print(f"Error sending packet: {e}")
                break
    if not quiet: print("Ping complete.")

def tcp(host, port, flags_str="S", sport=0, payload_str="", count=1, interval=1000, ttl=64, spoof_ip=None, verbose=False, quiet=False, win=5840, tcpseq=None, tcpack=None, badcksum=False, keep=False, data_size=0, scanner=False, timeout=2):
    """Sends a raw TCP packet."""
    wlan = network.WLAN(network.STA_IF)
    if not wlan.isconnected():
        if not quiet: print("WiFi is not connected.")
        return None if scanner else ...

    try:
        dst_ip = socket.getaddrinfo(host, port)[0][-1][0]
        src_ip = spoof_ip if spoof_ip else wlan.ifconfig()[0]
    except (IndexError, OSError) as e:
        if not quiet and not scanner: print(f"Error resolving host or getting local IP: {e}")
        return None if scanner else ...

    payload = payload_str.encode() if data_size == 0 else os.urandom(data_size)
    tcp_header_len = 20
    packet_len = 20 + tcp_header_len + len(payload)

    if sport == 0: sport = struct.unpack('!H', os.urandom(2))[0] % (65535 - 1024) + 1024

    seq_num = tcpseq if tcpseq is not None else struct.unpack('!I', os.urandom(4))[0]
    ack_num = tcpack if tcpack is not None else 0

    flags = 0
    if 'F' in flags_str.upper(): flags |= 1
    if 'S' in flags_str.upper(): flags |= 2
    if 'R' in flags_str.upper(): flags |= 4
    if 'P' in flags_str.upper(): flags |= 8
    if 'A' in flags_str.upper(): flags |= 16
    if 'U' in flags_str.upper(): flags |= 32
    if 'X' in flags_str.upper(): flags = 0b00101001 # FIN, PSH, URG
    if 'Y' in flags_str.upper(): flags = 0b00010010 # SYN, FIN, ACK

    tcp_header_no_chk = struct.pack('!HHIIBBHHH', sport, port, seq_num, ack_num, (5 << 4), flags, win, 0, 0)

    pseudo_hdr = _create_pseudo_header(src_ip, dst_ip, socket.IPPROTO_TCP, len(tcp_header_no_chk) + len(payload))
    chk = checksum(pseudo_hdr + tcp_header_no_chk + payload)
    if badcksum: chk = ~chk & 0xffff

    tcp_header = struct.pack('!HHIIBBHHH', sport, port, seq_num, ack_num, (5 << 4), flags, win, chk, 0)

    ip_header = _create_ip_header(src_ip, dst_ip, socket.IPPROTO_TCP, packet_len, ttl)

    packet = ip_header + tcp_header + payload

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        if not quiet and not scanner: print(f"Sending TCP to {host}:{port} from {src_ip}:{sport}")

        if scanner:
            s.settimeout(timeout)
            try:
                s.sendto(packet, (dst_ip, port))
                reply = s.recv(1024)
                r_tcp_header = reply[20:40]
                _, _, _, _, _, r_flags, _, _, _ = struct.unpack("!HHIIBBHHH", r_tcp_header)
                return r_flags
            except OSError:
                return None
        else:
            send_packets(s, packet, dst_ip, port, count, interval, quiet, verbose, keep, sport)
            if not quiet: print("TCP send complete.")

def udp(host, port, payload_str="hping", sport=0, count=1, interval=1000, ttl=64, spoof_ip=None, verbose=False, quiet=False, keep=False, data_size=0):
    """Sends a raw UDP packet."""
    wlan = network.WLAN(network.STA_IF)
    if not wlan.isconnected():
        if not quiet: print("WiFi is not connected.")
        return

    try:
        dst_ip = socket.getaddrinfo(host, port)[0][-1][0]
        src_ip = spoof_ip if spoof_ip else wlan.ifconfig()[0]
    except (IndexError, OSError) as e:
        if not quiet: print(f"Error resolving host or getting local IP: {e}")
        return

    payload = payload_str.encode() if data_size == 0 else os.urandom(data_size)
    udp_len = 8 + len(payload)
    packet_len = 20 + udp_len

    if sport == 0:
        sport = struct.unpack('!H', os.urandom(2))[0] % (65535 - 1024) + 1024

    udp_header_no_chk = struct.pack('!HHHH', sport, port, udp_len, 0)

    pseudo_hdr = _create_pseudo_header(src_ip, dst_ip, socket.IPPROTO_UDP, udp_len)
    chk = checksum(pseudo_hdr + udp_header_no_chk + payload)

    udp_header = struct.pack('!HHHH', sport, port, udp_len, chk)

    ip_header = _create_ip_header(src_ip, dst_ip, socket.IPPROTO_UDP, packet_len, ttl)

    packet = ip_header + udp_header + payload

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        if not quiet: print(f"Sending UDP to {host}:{port} from {src_ip}:{sport}")
        send_packets(s, packet, dst_ip, port, count, interval, quiet, verbose, keep, sport)
        if not quiet: print("UDP send complete.")

def traceroute(host, max_hops=30, timeout=2, ttl=1, keep_ttl=False, stop=False, no_rtt=False):
    """Performs a traceroute to the specified host."""
    try:
        dst_ip = socket.getaddrinfo(host, 0)[0][-1][0]
    except IndexError:
        print(f"Could not resolve host: {host}")
        return

    if not no_rtt:
        print(f"Traceroute to {host} ({dst_ip}), {max_hops} hops max")

    for i in range(max_hops):
        current_ttl = ttl if keep_ttl else ttl + i

        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as recv_socket, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as send_socket:

            recv_socket.settimeout(timeout)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, current_ttl)

            port = 33434 + i
            send_socket.sendto(b'', (dst_ip, port))

            curr_addr = None
            start_time = time.ticks_ms()

            try:
                reply, curr_addr = recv_socket.recvfrom(512)
                end_time = time.ticks_ms()
                curr_addr = curr_addr[0]

                if not no_rtt:
                    rtt = time.ticks_diff(end_time, start_time)
                    print(f"{current_ttl}\t{curr_addr}\t{rtt} ms")
                else:
                    print(f"{current_ttl}\t{curr_addr}")

                icmp_type = reply[20]
                if icmp_type == 3 and stop:
                    break

            except socket.timeout:
                if not no_rtt:
                    print(f"{current_ttl}\t*")

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
        flags = tcp(host, port, "S", timeout=timeout, scanner=True)

        if flags is not None and (flags & 0x12):
            print(f"Port {port} is OPEN")

    print("Scan complete.")
