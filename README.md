# 🔍 Flask Network Scanner (Nmap + Real-Time Visuals)

A Python Flask web-based network scanner that uses Nmap to enumerate hosts, open ports, services, and generate alerts + charts. Includes:

- JSON report generation
- Chart visualizations (Matplotlib)
- Alert system
- File upload & report viewer
- Downloadable scan reports
- Simple and clean UI (Jinja2 + Bootstrap)

---

## 🚀 Features
- Network discovery (`-sn`)
- Service detection (`-sV -T4`)
- JSON report creation
- Auto-generated charts:
  - Top open ports
  - Protocol distribution
  - Services per host
- Alert generation
- View reports in browser
- Download report button
- Upload existing `.json` reports

---
