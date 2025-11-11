# wifi.py
import wifi
import json
import os
import adafruit_logging as logging

# Set up logging
logger = logging.getLogger(__name__)

CONFIG_FILE = "wifi.json"

def save_config(ssid, password):
    """Saves the Wi-Fi configuration to a file."""
    config = {"ssid": ssid, "password": password}
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
        logger.info(f"Wi-Fi configuration saved for SSID: {ssid}")
    except OSError as e:
        logger.error(f"Failed to save Wi-Fi configuration: {e}")

def load_config():
    """Loads the Wi-Fi configuration from a file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        logger.warning(f"Could not load Wi-Fi configuration: {e}")
        return None

def connect():
    """Connects to the configured Wi-Fi network."""
    config = load_config()
    if config:
        logger.info(f"Connecting to {config['ssid']}...")
        try:
            wifi.radio.connect(config['ssid'], config['password'])
            logger.info(f"Connected to {config['ssid']}")
            logger.info(f"IP address: {wifi.radio.ipv4_address}")
            return True
        except ConnectionError as e:
            logger.error(f"Failed to connect to {config['ssid']}: {e}")
            return False
    else:
        logger.warning("Wi-Fi is not configured. Use 'set_wifi <ssid> <password>' to configure.")
        return False
