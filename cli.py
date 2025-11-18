import argparse
from scanner import network_scan, target_scan
from history import save_report
def main():
    parser = argparse.ArgumentParser(description="Scan hosts or network")
    parser.add_argument("--target", "-t", required=True, help="Target host or network")
    parser.add_argument("--file", "-f", default="host.json", help="Select a file for report")
    parser.add_argument("--ports", "-p", default=None, help="Optional ports to scan" )
    args = parser.parse_args()

    target = args.target.strip()
    file = args.file
    ports = args.ports
    if '/' in target:
        report = network_scan(target, file)
    else:
        report = target_scan(target, file, ports)

    path = save_report(report, file)
    print(f"report saved to {path}")
    print(f"Hosts found: {len(report.get('hosts', []))}, Services: {len(report.get('services', []))}")
if __name__ == "__main__":
    main()
