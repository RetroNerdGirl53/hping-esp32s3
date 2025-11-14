# wifi.py
import network
import json
import time
import os

CONFIG_FILE = "wifi.json"

def save_config(ssid, password):
    """Saves the Wi-Fi configuration to a file."""
    config = {"ssid": ssid, "password": password}
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
        print(f"Wi-Fi configuration saved for SSID: {ssid}")
    except OSError as e:
        print(f"Failed to save Wi-Fi configuration: {e}")

def load_config():
    """Loads the Wi-Fi configuration from a file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        print(f"Could not load Wi-Fi configuration: {e}")
        return None

def connect(timeout=15):
    """Connects to the configured Wi-Fi network with a timeout."""
    config = load_config()
    if not config:
        print("Wi-Fi is not configured. Use 'set_wifi <ssid> [password]' to configure.")
        return False

    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)

    if wlan.isconnected():
        print(f"Already connected to {wlan.config('essid')}")
        return True

    print(f"Connecting to {config['ssid']}...")
    wlan.connect(config['ssid'], config['password'])

    start_time = time.ticks_ms()
    while not wlan.isconnected():
        if time.ticks_diff(time.ticks_ms(), start_time) > timeout * 1000:
            status = wlan.status()
            if status == network.STAT_WRONG_PASSWORD:
                print("Connection failed: Wrong password.")
            elif status == network.STAT_NO_AP_FOUND:
                print("Connection failed: Access point not found.")
            else:
                print(f"Connection failed with status: {status}")
            wlan.disconnect()
            return False
        time.sleep_ms(500)

    print(f"Connected to {config['ssid']}")
    print(f"IP address: {wlan.ifconfig()[0]}")
    return True
