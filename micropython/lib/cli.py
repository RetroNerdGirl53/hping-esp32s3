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
            # This is a simple parser, we'll need to improve it for flags
            self.commands[command](*args)
        else:
            print(f"Unknown command: {command}")

def help_command():
    print("Available commands:")
    print("  help - Show this help message")
    print("  set_wifi <ssid> <password> - Configure Wi-Fi")
    print("  connect_wifi - Connect to the configured Wi-Fi network")
    print("  set_static_ip <ip> <subnet> <gateway> <dns> - Set a static IP address")
    print("  set_dhcp - Use DHCP")
    print("  ping <host> - Send ICMP echo requests to a host")
    print("  tcp <host> <port> [flags] - Send a TCP packet (e.g., tcp google.com 80 S)")
    print("  udp <host> <port> [payload] - Send a UDP packet")
    print("  scan <host> [ports] - Scan a host for open ports (e.g., scan google.com 1-1024)")


def set_wifi_command(ssid, password):
    wifi.save_config(ssid, password)

def connect_wifi_command():
    wifi.connect()

def set_static_ip_command(ip, subnet, gateway, dns):
    network.set_static_ip(ip, subnet, gateway, dns)

def set_dhcp_command():
    network.set_dhcp()

def ping_command(host):
    hping.ping(host)

def tcp_command(host, port, flags="S"):
    hping.tcp(host, int(port), flags)

def udp_command(host, port, payload="hping-micropython"):
    hping.udp(host, int(port), payload)

def scan_command(host, ports="1-1024"):
    hping.scan(host, ports)

def main():
    cli = CLI()
    cli.register("help", help_command)
    cli.register("set_wifi", set_wifi_command)
    cli.register("connect_wifi", connect_wifi_command)
    cli.register("set_static_ip", set_static_ip_command)
    cli.register("set_dhcp", set_dhcp_command)
    cli.register("ping", ping_command)
    cli.register("tcp", tcp_command)
    cli.register("udp", udp_command)
    cli.register("scan", scan_command)
    while True:
        try:
            command_line = input("> ")
            cli.execute(command_line)
        except KeyboardInterrupt:
            print("\nExiting...")
            break
