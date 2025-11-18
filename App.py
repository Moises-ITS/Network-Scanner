from flask import Flask, render_template, send_from_directory, abort, request, redirect, url_for, flash
import os, json, time
from history import REPORT_DIR, save_report, load_report
from visuals import generate_all_charts
from alerts import evaluate_alerts, save_alerts
from scanner import network_scan, normalize_banner, target_scan
from datetime import datetime, timedelta

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['SECRET_KEY'] = 'SUPERSECRETKEY'
os.makedirs(REPORT_DIR, exist_ok=True)

ALERTS_DIR = "alerts"
os.makedirs(ALERTS_DIR, exist_ok=True)

@app.route("/")
def index():
    reports = sorted(os.listdir(REPORT_DIR))
    return render_template("index.html", reports=reports)

@app.route("/report_view")
def report_view():
    filename = request.args.get("filename")
    if filename not in os.listdir(REPORT_DIR):
        abort(404)
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    report = data.get("report") or data
    services = report.get("services", [])
    charts = generate_all_charts(services)
    alerts = evaluate_alerts(services)
    alerts_file = save_alerts(alerts, f"{filename[:-5]}_alerts.json")
    if request.method == "POST":
        download_report(filename)
        return redirect(url_for("/"))
    return render_template("report_view.html", filename=filename, services=services, report=report, charts=charts, alerts=alerts, alerts_file=os.path.basename(alerts_file))

@app.route("/scan", methods=["POST", "GET"])
def scan():
    if request.method == "POST":
        target = request.form.get("target")
        scan_type = request.form.get("scan_type")
        if not target:
            flash("Please enter a target IP or network")
            return redirect(url_for("scan"))
        for i in target:
            if i.isalpha():
                flash("NO LETTERS ALLOWED")
                return redirect(url_for("scan"))
        if "." not in target:
            flash("must be a valid Host or Network")
            return redirect(url_for("/scan"))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('/', '_')}_{timestamp}.json"
        save_path = os.path.join(REPORT_DIR, filename)
        if scan_type == "network" and "/" not in target:
            flash("Incorrect network Notation( USE CIDR )")
            return redirect(url_for("scan"))
        if scan_type == "host" and "/" in target:
            flash("Incorrect host Notation ( Don't use / )")
            return redirect(url_for("scan"))
        if scan_type == "network":
            report = network_scan(target)
            save_report(report, save_path)
        else:
            report = target_scan(target)
            save_report(report, save_path)
        alerts = evaluate_alerts(report.get("services"))
        save_alerts(alerts, f"{filename}_alerts.json")
        services = report.get("services")
        charts = generate_all_charts(services)
        return render_template("/report_view.html", report=report, alerts=alerts, services=services, charts=charts, filename=filename, target=target, scan_type=scan_type, alerts_file=f"{filename}_alerts.json")
    return render_template("/scan.html")

@app.route("/report_upload", methods=["POST", "GET"])
def report_upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            return "No file uploaded", 400
        filename = f.filename
        if not filename.endswith(".json"):
            return "File must end with .json", 400
        save_path = os.path.join(REPORT_DIR, filename)
        f.save(save_path)
        return redirect(url_for("/"))
    return render_template("report_upload.html")
@app.route('/download/<filename>')
def download_report(filename):
    if filename not in os.listdir(REPORT_DIR):
        abort(404)
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
