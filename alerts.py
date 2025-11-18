import json
import os
from email.mime.text import MIMEText

ALERTS_DIR = "alerts"
os.makedirs(ALERTS_DIR, exist_ok=True)

def ssh_rule_notstandard(service):
    return service.get("service_name") in ("ssh",) and int(service.get("port", 0)) != 22

def rdp_rule_open(service):
    return service.get("service_name") in ("ms-wbt-server", "rdp",) or int(service.get("port", 0)) == 3389

def telnet_rule_open(service):
    return service.get("service_name") in ("telnet",) or int(service.get("port", 0)) == 23

def ftp_rule_open(service):
    return service.get("service_name") in ("ftp",) or int(service.get("port", 0)) == 21

def rule_unusual_http(service):
    name = (service.get("service_name" ) or "").lower()
    return (name in ("http", "https") and service.get("port") not in (80, 443))

def rule_unkown_product(service):
    return not service.get("product") and service.get("state") == "open"

ALERT_RULES = [
    ("SSH_NOTSTANDARD", "SSH running on a non-default port (not 22)", ssh_rule_notstandard),
    ("RDP_OPEN", "RDP detected(rdp/ms-wbt-server or port 3389 detected)", rdp_rule_open),
    ("TELNET_OPEN", "Telnet detected(telnet or port 23 detcected)", telnet_rule_open),
    ("FTP_OPEN", "FTP detected(FTP or port 21 detected)", ftp_rule_open),
    ("HTTP_UNUSUAL_PORT", "HTTP detected on unusual port", rule_unusual_http),
    ("UNKOWN_SERVICE", "Unown service running on an open port", rule_unkown_product)
]

def evaluate_alerts(services):
    alerts = []
    for svc in services:
        for rule_id, desc, predicate in ALERT_RULES:
            try:
                if predicate(svc):
                    alert = {
                        "rule": rule_id,
                        "desc": desc,
                        "host": svc.get("host"),
                        "port": svc.get("port"),
                        "service_name": svc.get("service_name"),
                        "product": svc.get("product"),
                        "version": svc.get("version")
                    }
                    alerts.append(alert)
            except Exception as e:
                print(f"Error has occured: {e}")
    return alerts
def save_alerts(alerts, out_file):
    file_path = os.path.join(ALERTS_DIR, out_file)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    return out_file
