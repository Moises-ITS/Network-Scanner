import os
import json

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

def save_report(report, path):
    with open(path, "w", encoding='utf-8') as f:
        json.dump(report, f, indent=2)

def load_report(filename):
    path = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)
