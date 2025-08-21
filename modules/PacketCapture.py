from scapy.all import sniff


class PacketCapture:
    def __init__(self, ifaces, analyzer):
        self.ifaces = ifaces
        self.analyzer = analyzer

    def start(self):
        if isinstance(self.ifaces, list):
            print(f"Listening on multiple interfaces: {', '.join(self.ifaces)}")
        else:
            print(f"Listening on {self.ifaces} ...")

        sniff(iface=self.ifaces, prn=self.analyzer.analyze, store=False)
