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

def main():
    cli = CLI()
    cli.register("help", help_command)
    cli.register("set_wifi", set_wifi_command)
    cli.register("connect_wifi", connect_wifi_command)
    cli.register("set_static_ip", set_static_ip_command)
    cli.register("set_dhcp", set_dhcp_command)
    cli.register("ping", ping_command)
    while True:
        try:
            command_line = input("> ")
            cli.execute(command_line)
        except KeyboardInterrupt:
            print("\nExiting...")
            break
