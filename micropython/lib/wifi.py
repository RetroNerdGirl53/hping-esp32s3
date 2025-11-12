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

def connect():
    """Connects to the configured Wi-Fi network."""
    config = load_config()
    if config:
        print(f"Connecting to {config['ssid']}...")
        wlan = network.WLAN(network.STA_IF)
        wlan.active(True)
        if not wlan.isconnected():
            wlan.connect(config['ssid'], config['password'])
            while not wlan.isconnected():
                time.sleep(1)
        print(f"Connected to {config['ssid']}")
        print(f"IP address: {wlan.ifconfig()[0]}")
        return True
    else:
        print("Wi-Fi is not configured. Use 'set_wifi <ssid> <password>' to configure.")
        return False
