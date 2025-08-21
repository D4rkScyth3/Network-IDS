import os
from datetime import datetime
from .AlertSystem import AlertSystem


class IntrusionDetectionSystem:
    def __init__(self, alert_system: AlertSystem = None, logs_dir="logs"):
        self.logs_dir = logs_dir
        os.makedirs(self.logs_dir, exist_ok=True)
        self.alert_system = alert_system or AlertSystem(self.logs_dir)

    def _detections_file(self):
        today = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.logs_dir, f"detections_{today}.log")

    def log_detection(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self._detections_file(), "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
