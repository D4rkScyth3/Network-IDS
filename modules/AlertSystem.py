from datetime import datetime
import os


class AlertSystem:
    def __init__(self, logs_dir="logs"):
        self.logs_dir = logs_dir
        os.makedirs(self.logs_dir, exist_ok=True)

    def send_alert(self, message):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file = os.path.join(self.logs_dir, "alerts.log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
        print(f"ALERT: {message}")
