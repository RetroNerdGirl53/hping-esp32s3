# main.py
from lib import cli

def main():
    """
    Main entry point for the application.
    """
    print("Starting hping3 port for MicroPython")
    print("Type 'help' for a list of commands.")

    c = cli.CLI()
    c.register("help", cli.help_command)
    c.register("set_wifi", cli.set_wifi_command)
    c.register("connect_wifi", cli.connect_wifi_command)
    c.register("set_static_ip", cli.set_static_ip_command)
    c.register("set_dhcp", cli.set_dhcp_command)
    c.register("discover", cli.discover_command)
    c.register("profile", cli.profile_command)
    c.register("ping", cli.ping_command)
    c.register("tcping", cli.tcping_command)
    c.register("traceroute", cli.traceroute_command)
    c.register("tcp", cli.tcp_command)
    c.register("udp", cli.udp_command)
    c.register("scan", cli.scan_command)

    while True:
        try:
            command_line = input("> ")
            c.execute(command_line)
        except KeyboardInterrupt:
            print("\nExiting...")
            break

if __name__ == "__main__":
    main()
