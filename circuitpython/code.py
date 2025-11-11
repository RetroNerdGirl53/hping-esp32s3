# code.py
import supervisor
import sys
import adafruit_logging as logging
from lib.cli import CLI, help_command, set_wifi_command, connect_wifi_command, set_static_ip_command, set_dhcp_command, ping_command

def main():
    """
    Main entry point for the application.
    This function will be called by the CircuitPython runtime.
    """
    # Configure logging
    logger = logging.getLogger('hping')
    logger.setLevel(logging.INFO)

    # Create a handler to write to the serial console
    stream_handler = logging.StreamHandler(sys.stdout)
    logger.addHandler(stream_handler)

    logger.info("Starting hping3 port for CircuitPython")
    logger.info("Type 'help' for a list of commands.")

    cli = CLI()
    cli.register("help", help_command)
    cli.register("set_wifi", set_wifi_command)
    cli.register("connect_wifi", connect_wifi_command)
    cli.register("set_static_ip", set_static_ip_command)
    cli.register("set_dhcp", set_dhcp_command)
    cli.register("ping", ping_command)

    while True:
        if supervisor.runtime.serial_bytes_available:
            command_line = sys.stdin.readline()
            cli.execute(command_line)

if __name__ == "__main__":
    main()
