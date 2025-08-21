from scapy.layers.inet import TCP, IP


class TrafficAnalyzer:
    def __init__(self, alert_system):
        self.alert_system = alert_system
        self.suspicious_patterns = [
            b"' or '1'='1",   # SQLi
            b"union select",  # SQLi
            b"<script>",      # XSS
            b" or 1=1",       # SQLi
            b"sleep(",        # SQLi
        ]

    def analyze(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(IP):
            payload = bytes(packet[TCP].payload)

            # Rule 1: Suspicious payload patterns
            for sig in self.suspicious_patterns:
                if sig in payload.lower():
                    self.alert_system.send_alert(
                        f"Suspicious payload from {packet[IP].src}: {sig.decode(errors='ignore')}"
                    )

            # Rule 2: Possible port scan (SYN packet without ACK)
            if packet[TCP].flags == "S":
                self.alert_system.send_alert(
                    f"Possible port scan from {packet[IP].src} on port {packet[TCP].dport}"
                )
