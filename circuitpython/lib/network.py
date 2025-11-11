# network.py
import wifi
import ipaddress
import adafruit_logging as logging

# Set up logging
logger = logging.getLogger(__name__)

def set_static_ip(ip, subnet, gateway, dns):
    """Sets a static IP address."""
    try:
        ipv4 = ipaddress.IPv4Address(ip)
        netmask = ipaddress.IPv4Address(subnet)
        gw = ipaddress.IPv4Address(gateway)
        dns_server = ipaddress.IPv4Address(dns)
        wifi.radio.set_ipv4_address(ipv4=ipv4, netmask=netmask, gateway=gw, ipv4_dns=dns_server)
        logger.info(f"Set static IP address: {wifi.radio.ipv4_address}")
    except ValueError as e:
        logger.error(f"Invalid IP address: {e}")

def set_dhcp():
    """Sets the device to use DHCP."""
    wifi.radio.set_ipv4_address(ipv4=None, netmask=None, gateway=None, ipv4_dns=None)
    logger.info("Set to use DHCP")
