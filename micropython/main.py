# main.py
from lib.cli import CLI, help_command, set_wifi_command, connect_wifi_command, set_static_ip_command, set_dhcp_command, ping_command, tcp_command, udp_command, scan_command, traceroute_command

def main():
    """
    Main entry point for the application.
    """
    print("Starting hping3 port for MicroPython")
    print("Type 'help' for a list of commands.")

    cli = CLI()
    cli.register("help", help_command)
    cli.register("set_wifi", set_wifi_command)
    cli.register("connect_wifi", connect_wifi_command)
    cli.register("set_static_ip", set_static_ip_command)
    cli.register("set_dhcp", set_dhcp_command)
    cli.register("ping", ping_command)
    cli.register("traceroute", traceroute_command)
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

if __name__ == "__main__":
    main()
