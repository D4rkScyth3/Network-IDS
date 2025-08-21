import sys
import psutil

from modules.PacketCapture import PacketCapture
from modules.TrafficAnalyzer import TrafficAnalyzer
from modules.AlertSystem import AlertSystem
from modules.IntrusionDetectionSystem import IntrusionDetectionSystem


def list_active_interfaces():
    """Return all active interfaces (with IPv4, skip loopback)."""
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2 and addr.address != "127.0.0.1":  # IPv4 only
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
