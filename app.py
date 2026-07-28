import os
import json
import math
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file

import analyzer

app = Flask(__name__, template_folder="templates", static_folder="static")

def calculate_ip_location(ip):
    """Generates deterministic mock location tags for SOC grid UI based on IP prefix."""
    if not ip or ip == "None":
        return "Unknown"
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
        return "Internal / LAN"
    elif ip.startswith("172.20."):
        return "US - Virginia Datacenter"
    elif ip.startswith("172."):
        return "EU - Frankfurt Cloud"
    elif ip.startswith("192."):
        return "US - New York"
    elif ip.startswith("10."):
        return "AP - Tokyo Region"
    else:
        return "Global / External WAN"

def enrich_analysis_data(results, log_text):
    """
    Enriches backend analysis results with enterprise SOC metadata:
    - Global Threat Level Score
    - Risk Scores per IP & User
    - Activity Timeline Execution Steps
    - Data Grid Objects
    """
    summary = results.get("summary", {})
    detections = results.get("detections", {})
    failed_ips = results.get("failed_logins_by_ip", {})
    failed_users = results.get("failed_logins_by_user", {})
    
    brute_alerts = detections.get("brute_force", {}).get("alerts", [])
    spray_alerts = detections.get("password_spraying", {}).get("alerts", [])
    
    total = summary.get("total_login_attempts", 0)
    failed = summary.get("failed_login_attempts", 0)
    malformed = summary.get("malformed_log_entries", 0)
    
    # 1. Threat Score Calculation (0 to 100)
    threat_score = 0
    if total > 0:
        fail_ratio = (failed / total) * 40 # Up to 40 points for high failure ratio
        threat_score += fail_ratio
        
    threat_score += len(brute_alerts) * 25 # +25 for each brute force attack IP
    threat_score += len(spray_alerts) * 25 # +25 for each password spray attack IP
    threat_score = min(100, max(5, round(threat_score)))
    
    if threat_score >= 70 or len(brute_alerts) > 0 or len(spray_alerts) > 0:
        threat_level = "CRITICAL"
        threat_color = "red"
    elif threat_score >= 35:
        threat_level = "ELEVATED"
        threat_color = "amber"
    else:
        threat_level = "NORMAL"
        threat_color = "green"
        
    # Set of IPs flagged by detections
    flagged_ips = set(a.get("ip") for a in brute_alerts + spray_alerts)
    
    # 2. Suspicious IPs Grid Data
    suspicious_ips_grid = []
    max_ip_attempts = max(failed_ips.values()) if failed_ips else 1
    
    for ip, count in sorted(failed_ips.items(), key=lambda x: x[1], reverse=True):
        is_flagged = ip in flagged_ips
        if is_flagged or count >= 5:
            risk = "CRITICAL"
            status = "ATTACK VECTOR"
        elif count >= 3:
            risk = "HIGH"
            status = "FLAGGED"
        elif count >= 2:
            risk = "MEDIUM"
            status = "SUSPICIOUS"
        else:
            risk = "LOW"
            status = "MONITORED"
            
        suspicious_ips_grid.append({
            "ip": ip,
            "failed_attempts": count,
            "risk_score": risk,
            "status": status,
            "location": calculate_ip_location(ip),
            "last_seen": "Recent Activity"
        })
        
    # 3. Targeted Users Grid Data
    targeted_users_grid = []
    max_user_attempts = max(failed_users.values()) if failed_users else 1
    
    for username, count in sorted(failed_users.items(), key=lambda x: x[1], reverse=True):
        if count >= 5:
            risk = "HIGH"
            status = "CRITICAL TARGET"
        elif count >= 3:
            risk = "MEDIUM"
            status = "TARGETED"
        else:
            risk = "LOW"
            status = "MONITORED"
            
        targeted_users_grid.append({
            "username": username,
            "failed_attempts": count,
            "risk_score": risk,
            "status": status
        })
        
    # 4. Activity Execution Timeline Steps
    line_count = len([l for l in log_text.splitlines() if l.strip()])
    timestamp_now = datetime.now().strftime("%H:%M:%S EST")
    
    activity_timeline = [
        {
            "time": timestamp_now,
            "title": "Log Data Ingestion",
            "desc": f"Ingested {line_count} log stream entries.",
            "status": "completed"
        },
        {
            "time": timestamp_now,
            "title": "Security Log Parser",
            "desc": f"Identified {summary.get('successful_login_attempts', 0)} success, {failed} failed, {malformed} malformed entries.",
            "status": "completed"
        },
        {
            "time": timestamp_now,
            "title": "Threat Detection Engine",
            "desc": f"Brute-force: {len(brute_alerts)} alerts | Password Spraying: {len(spray_alerts)} alerts.",
            "status": "completed"
        },
        {
            "time": timestamp_now,
            "title": "Security Report Artifacts Generated",
            "desc": "analysis_results.json & Security_Report.txt updated.",
            "status": "completed"
        }
    ]
    
    return {
        "threat_score": threat_score,
        "threat_level": threat_level,
        "threat_color": threat_color,
        "suspicious_ips_grid": suspicious_ips_grid,
        "targeted_users_grid": targeted_users_grid,
        "activity_timeline": activity_timeline,
        "last_analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze_logs_endpoint():
    try:
        log_text = None

        if "file" in request.files:
            uploaded_file = request.files["file"]
            if uploaded_file.filename != "":
                file_bytes = uploaded_file.read()
                try:
                    log_text = file_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    log_text = file_bytes.decode("latin-1", errors="replace")

        if not log_text and request.is_json:
            data = request.get_json() or {}
            log_text = data.get("log_text")

        if not log_text and "log_text" in request.form:
            log_text = request.form.get("log_text")

        if not log_text or not log_text.strip():
            return jsonify({
                "success": False,
                "error": "No log data provided. Please paste log text or upload a log file."
            }), 400

        # Execute existing Python analyzer logic unmodified
        results = analyzer.analyze_logs(log_text)

        # Save results and report using existing backend functions
        analyzer.save_results(results)
        analyzer.generate_report(results)

        # Enriched metadata for enterprise SOC UI
        enriched = enrich_analysis_data(results, log_text)

        # Read generated report content
        report_content = ""
        if os.path.exists(analyzer.REPORT_FILE):
            with open(analyzer.REPORT_FILE, "r", encoding="utf-8") as f:
                report_content = f.read()

        return jsonify({
            "success": True,
            "results": results,
            "enriched": enriched,
            "report": report_content
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Analysis failed: {str(e)}"
        }), 500

@app.route("/api/download/report", methods=["GET"])
def download_report():
    if os.path.exists(analyzer.REPORT_FILE):
        return send_file(
            analyzer.REPORT_FILE,
            mimetype="text/plain",
            as_attachment=True,
            download_name="Security_Report.txt"
        )
    return jsonify({"error": "Report file not found."}), 404

@app.route("/api/download/json", methods=["GET"])
def download_json():
    if os.path.exists(analyzer.RESULTS_FILE):
        return send_file(
            analyzer.RESULTS_FILE,
            mimetype="application/json",
            as_attachment=True,
            download_name="analysis_results.json"
        )
    return jsonify({"error": "Results JSON file not found."}), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Elite SOC Log Analyzer Server on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
