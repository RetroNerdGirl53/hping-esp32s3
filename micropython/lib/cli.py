# cli.py
from lib import wifi
from lib import network
from lib import hping

class CLI:
    def __init__(self):
        self.commands = {}

    def register(self, name, function):
        self.commands[name] = function

    def execute(self, command_line):
        parts = command_line.strip().split()
        if not parts:
            return
        command = parts[0]
        args = parts[1:]
        if command in self.commands:
            self.commands[command](args)
        else:
            print(f"Unknown command: '{command}'. Type 'help' for a list of commands.")

def help_command(args):
    print("--- hping for MicroPython ---")
    print("An extensible network tool for the ESP32-S3.\n")
    print("Usage: <command> [arguments] [--options ...]\n")
    print("Commands:")
    print("  help                 Show this help message")
    print("  set_wifi <ssid> [pw] Save WiFi SSID and password (pw is optional for open nets)")
    print("  connect_wifi         Connect to the saved WiFi")
    print("  set_static_ip ...    Set a static IP address")
    print("  set_dhcp             Enable DHCP for IP address")
    print("  discover             Discover live hosts on the network")
    print("  profile <host>       Guess the role of a host on the network")
    print("  ping <host>          Send ICMP echo requests")
    print("  tcping <host> <port> Send a TCP SYN packet and wait for a reply")
    print("  tcp <host> <port>    Send a custom TCP packet")
    print("  udp <host> <port>    Send a UDP packet")
    print("  traceroute <host>    Trace the path to a host")
    print("  scan <host> [ports]  Scan a host for open TCP ports\n")

def parse_args(args):
    pos_args = []
    kw_args = {}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith('--'):
            key = arg[2:]
            if i + 1 < len(args) and not args[i+1].startswith('--'):
                kw_args[key] = args[i+1]
                i += 2
            else:
                kw_args[key] = True
                i += 1
        else:
            pos_args.append(arg)
            i += 1
    return pos_args, kw_args

# --- Command Handlers ---

def set_wifi_command(args):
    pos_args, _ = parse_args(args)
    if len(pos_args) == 1:
        wifi.save_config(pos_args[0], "")
    elif len(pos_args) == 2:
        wifi.save_config(pos_args[0], pos_args[1])
    else:
        print("Usage: set_wifi <ssid> [password]")

def connect_wifi_command(args):
    wifi.connect()

def set_static_ip_command(args):
    pos_args, _ = parse_args(args)
    if len(pos_args) == 4:
        network.set_static_ip(*pos_args)
    else:
        print("Usage: set_static_ip <ip> <subnet> <gateway> <dns>")

def set_dhcp_command(args):
    network.set_dhcp()

def discover_command(args):
    hping.discover()

def profile_command(args):
    pos_args, _ = parse_args(args)
    if pos_args:
        hping.profile(pos_args[0])
    else:
        print("Usage: profile <host>")

def ping_command(args):
    pos_args, kw_args = parse_args(args)
    if pos_args:
        hping.ping(pos_args[0])
    else:
        print("Usage: ping <host>")

def tcping_command(args):
    pos_args, kw_args = parse_args(args)
    if len(pos_args) == 2:
        hping.tcping(pos_args[0], int(pos_args[1]))
    else:
        print("Usage: tcping <host> <port>")

def traceroute_command(args):
    pos_args, _ = parse_args(args)
    if pos_args:
        hping.traceroute(pos_args[0])
    else:
        print("Usage: traceroute <host>")

def tcp_command(args):
    pos_args, kw_args = parse_args(args)
    if len(pos_args) >= 2:
        hping.tcp(pos_args[0], int(pos_args[1]))
    else:
        print("Usage: tcp <host> <port>")

def udp_command(args):
    pos_args, kw_args = parse_args(args)
    if len(pos_args) >= 2:
        hping.udp(pos_args[0], int(pos_args[1]))
    else:
        print("Usage: udp <host> <port>")

def scan_command(args):
    pos_args, _ = parse_args(args)
    if pos_args:
        ports = pos_args[1] if len(pos_args) > 1 else "1-1024"
        hping.scan(pos_args[0], ports)
    else:
        print("Usage: scan <host> [ports]")
