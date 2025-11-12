# network.py
import network

def set_static_ip(ip, subnet, gateway, dns):
    """Sets a static IP address."""
    wlan = network.WLAN(network.STA_IF)
    wlan.ifconfig((ip, subnet, gateway, dns))
    print(f"Set static IP address: {wlan.ifconfig()[0]}")

def set_dhcp():
    """Sets the device to use DHCP."""
    wlan = network.WLAN(network.STA_IF)
    wlan.ifconfig('dhcp')
    print("Set to use DHCP")
