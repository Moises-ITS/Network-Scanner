import nmap
from datetime import datetime, timedelta
import time
import re
def normalize_banner(product, version):
    p = (product or '').strip()
    p = re.sub(r'\s*\(.*?\)\s*$', '', p)
    p = re.sub(r'[_/\\]+', ' ', p)  
    p = p.lower()
    v = (version or '').strip()
    m = re.search(r'(\d+(\.\d+){0,3})', v)
    if m:
        v = m.group(1)
    else:
        v = v.split()[0] if v else ""
    
    return p, v

def network_scan(target, ports=None):
    nm = nmap.PortScanner()
    raw_start = time.time()
    start = datetime.fromtimestamp(raw_start).strftime("%Y-%m-%d %H:%M:%S")
    nm.scan(hosts=target, arguments='-sn')
    hosts = nm.all_hosts()
    
    main = []
    args = "-sV -T4"
    if ports:
        args += f" -p {ports}"

    for host in hosts:
        nm.scan(hosts=host, arguments=args)
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                info = nm[host][proto][port]
                raw_product = info.get("product") or ''
                raw_version = info.get("version") or ''
                product, version = normalize_banner(raw_product, raw_version)
                services = {
                    'host': host,
                    'protocol': proto,
                    'port': port,
                    'name': info.get('name'),
                    'state': info.get('state'),
                    'product': product,
                    'version': version,
                    'extrainfo': info.get('extrainfo')
                }
                main.append(services)
    duration = round(time.time() - raw_start, 2)
    return {
        "meta" : {
            "type": "discovery",
            "target": target,
            "started": start,
            "duration": duration,
            "nmap_version": nm.nmap_version()
        },
        "hosts": hosts,
        "services": main
}
 

def target_scan(target, file="host.json", ports=None):
    nm = nmap.PortScanner()
    args = "-sV -T4"
    if ports:
        args += f" -p {ports}"
    raw_start = time.time()
    start = datetime.fromtimestamp(raw_start).strftime("%Y-%m-%d %H:%M:%S")
    nm.scan(hosts=target, arguments=args)
    duration = time.time() - raw_start
    duration = round(duration, 2)
    hosts = nm.all_hosts()
    sheet = []
    for host in hosts:
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                raw_product = info.get('product') or ''
                raw_version = info.get('version') or ''
                product, version = normalize_banner(raw_product, raw_version)
                services = {
                    'host': host,
                    'protocol': proto,
                    'port': port,
                    'name': info.get('name'),
                    'state': info.get('state'),
                    'product': product,
                    'version': version,
                    'extrainfo': info.get('extrainfo')
                }
                sheet.append(services)
    return {
        "meta": {
            "Type": "Discovery",
            "Target": target,
            "port(s)": ports or "default",
            "Start": start,
            "Duration": duration,
            "Nmap_Version": nm.nmap_version()

        },
        "hosts": hosts,
        "services": sheet
    }
