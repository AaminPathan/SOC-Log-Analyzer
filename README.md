# 🛡️ SOC Log Analyzer

A Python-based Security Operations Center (SOC) Log Analyzer that parses authentication logs, detects suspicious login activity, and generates detailed security reports.

---

## 📌 Features

- Detects failed login attempts
- Detects successful logins
- Counts failed logins per user
- Counts failed logins per IP
- Identifies the most suspicious IP
- Identifies the user with the highest failed login attempts
- Detects potential brute-force attacks
- Supports flexible log parsing (not fixed-position parsing)
- Detects duplicate log analysis using SHA-256 hashing
- Generates detailed security reports
- Supports log input through text or file

---

## 🛠️ Technologies Used

- Python 3
- File Handling
- Dictionaries
- JSON
- SHA-256 Hashing
- Modular Programming

---

## 📂 Project Structure

```
SOC_Log_Analyzer/
│
├── analyzer.py
├── logs/
│   └── logs.txt
├── analysis_metadata.json
├── Security_Report.txt
├── README.md
└── .gitignore
```

---

## 🚀 How to Run

Clone the repository

```bash
git clone <repository-url>
```

Move into the project

```bash
cd SOC_Log_Analyzer
```

Run

```bash
python analyzer.py
```

The program allows users to:

- Analyze logs from a file
- Paste log text directly
- Generate a detailed SOC security report

---

## 📋 Sample Output

```
===== SECURITY REPORT =====

Total Login Attempts : 29
Failed Login Attempts : 22
Successful Login Attempts : 7

User with Highest Failed Attempts : admin
Most Suspicious IP : 192.168.1.10

Potential Brute Force : YES
Severity : HIGH
```

---

## 🔮 Future Improvements

- Real-time log monitoring
- Timestamp-based attack detection
- Password spraying detection
- Live dashboard
- Email alerting
- Threat Intelligence integration
- MITRE ATT&CK mapping
- Wazuh Integration
- Splunk Integration
- Sigma Rule support

---

## 🎯 Purpose

This project was built to strengthen practical SOC Analyst skills by simulating real-world log analysis and security event detection.

---

## 👨‍💻 Author

**Aamin Pathan**

Aspiring SOC Analyst | Cybersecurity Enthusiast