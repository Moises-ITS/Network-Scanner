import os
import matplotlib.pyplot as plt
from collections import Counter
import matplotlib
matplotlib.use('Agg')  # non-GUI backend for Flask
import matplotlib.pyplot as plt

STATIC_DIR = "static"
os.makedirs(STATIC_DIR, exist_ok=True)

def chart_ports(services, out_file="/ports_distribution.png"):
    ports = []
    for service in services:
        port = service.get("port")
        if port is not None:
            ports.append(str(port))
    counts = Counter(ports)
    top = counts.most_common(3)
    if not top:
        return None
    labels, values = zip(*top)
    plt.figure(figsize=(8,4))
    plt.bar(labels, values)
    plt.title("Top 3 Open Ports")
    plt.xlabel("Ports")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()
    return out_file

def chart_protocol_distorbution(services, out_file="/protocols_pie.png"):
    protos = []
    for p in services:
        protocol = p.get("protocol")
        if protocol is not None:
            protos.append(str(protocol))
    counts = Counter(protos)
    labels = counts.keys()
    sizes = counts.values()
    if not sizes:
        return None
    plt.figure(figsize=(5,5))
    plt.pie(sizes,  labels=labels, autopct="%1.1f%%", startangle=140)
    plt.title("Protocol Distribution")
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()
    return out_file


def generate_all_charts(services):
    out = {}
    p = chart_ports(services)
    if p:
        out["ports_distribution"] = p
    p = chart_protocol_distorbution(services)
    if p:
        out["protocol_pie"] = p
    return out
