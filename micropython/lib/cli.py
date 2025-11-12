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
            print(f"Unknown command: {command}")

def help_command(args):
    print("Available commands:")
    print("  help")
    print("  set_wifi <ssid> <password>")
    print("  connect_wifi")
    print("  set_static_ip <ip> <subnet> <gateway> <dns>")
    print("  set_dhcp")
    print("  ping <host>")
    print("  traceroute <host>")
    print("  tcp <host> <port> [flags] [--sport <port>] [--data <payload>]")
    print("  udp <host> <port> [--sport <port>] [--data <payload>]")
    print("  scan <host> [ports]")

def parse_args(args):
    """A simple keyword argument parser."""
    pos_args = []
    kw_args = {}
    i = 0
    while i < len(args):
        if args[i].startswith('--'):
            if i + 1 < len(args):
                kw_args[args[i][2:]] = args[i+1]
                i += 2
            else: # Handle flag with no value
                i += 1
        else:
            pos_args.append(args[i])
            i += 1
    return pos_args, kw_args

def set_wifi_command(args):
    pos_args, _ = parse_args(args)
    if len(pos_args) == 2:
        wifi.save_config(pos_args[0], pos_args[1])
    else:
        print("Usage: set_wifi <ssid> <password>")

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

def ping_command(args):
    pos_args, _ = parse_args(args)
    if pos_args:
        hping.ping(pos_args[0])
    else:
        print("Usage: ping <host>")

def traceroute_command(args):
    pos_args, _ = parse_args(args)
    if pos_args:
        hping.traceroute(pos_args[0])
    else:
        print("Usage: traceroute <host>")

def tcp_command(args):
    pos_args, kw_args = parse_args(args)
    if len(pos_args) >= 2:
        host = pos_args[0]
        port = int(pos_args[1])
        flags = pos_args[2] if len(pos_args) > 2 else "S"
        sport = int(kw_args.get("sport", 0))
        data = kw_args.get("data", "")
        hping.tcp(host, port, flags, sport, data)
    else:
        print("Usage: tcp <host> <port> [flags] [--sport <port>] [--data <payload>]")

def udp_command(args):
    pos_args, kw_args = parse_args(args)
    if len(pos_args) == 2:
        host = pos_args[0]
        port = int(pos_args[1])
        sport = int(kw_args.get("sport", 0))
        data = kw_args.get("data", "hping")
        hping.udp(host, port, data, sport)
    else:
        print("Usage: udp <host> <port> [--sport <port>] [--data <payload>]")

def scan_command(args):
    pos_args, _ = parse_args(args)
    if pos_args:
        ports = pos_args[1] if len(pos_args) > 1 else "1-1024"
        hping.scan(pos_args[0], ports)
    else:
        print("Usage: scan <host> [ports]")
