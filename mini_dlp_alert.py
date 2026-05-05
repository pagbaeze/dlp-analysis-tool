import csv
from collections import defaultdict
from datetime import datetime

INPUT_FILE = "dlp_events.csv"
OUTPUT_FILE = "dlp_alert_report.txt"

LARGE_FILE_MB = 100
UPLOAD_THRESHOLD = 3
BULK_FILE_COUNT = 10

SENSITIVE_FILE_TYPES = {".xlsx", ".csv", ".pdf", ".docx", ".zip", ".rar", ".7z"}
ARCHIVE_TYPES = {".zip", ".rar", ".7z"}

SENSITIVE_KEYWORDS = {
    "ssn", "social security", "payroll", "salary", "w2", "tax",
    "confidential", "customer", "password", "credentials",
    "employee", "legal", "contract", "restricted"
}

PERSONAL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "icloud.com"}
COMPANY_DOMAINS = {"company.com", "company-sharepoint.com", "company-onedrive.com"}

HIGH_RISK_DEPARTMENTS = {"Finance", "HR", "Legal"}
HIGH_RISK_EMPLOYMENT_STATUS = {"Departing", "Terminated"}

AFTER_HOURS_START = 20
AFTER_HOURS_END = 6

upload_count = defaultdict(int)
alerts = []

def get_domain(destination):
    if "@" in destination:
        return destination.split("@")[-1].lower()
    return destination.lower()

def get_file_extension(filename):
    if "." in filename:
        return "." + filename.split(".")[-1].lower()
    return ""

def get_severity(score):
    if score >= 90:
        return "High"
    elif score >= 50:
        return "Medium"
    else:
        return "Low"

with open(INPUT_FILE, "r", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)

    for row in reader:
        timestamp = row["timestamp"]
        user = row["user"]
        department = row["department"]
        employment_status = row["employment_status"]
        filename = row["filename"]
        file_size_mb = int(row["file_size_mb"])
        file_count = int(row["file_count"])
        classification = row["classification"]
        destination = row["destination"]
        action = row["action"]

        risk_score = 0
        reasons = []

        upload_count[user] += 1

        filename_lower = filename.lower()
        file_extension = get_file_extension(filename)
        destination_domain = get_domain(destination)

        if action.lower() == "upload":

            if file_size_mb >= LARGE_FILE_MB:
                risk_score += 30
                reasons.append(f"Large file upload: {file_size_mb} MB")

            if file_extension in SENSITIVE_FILE_TYPES:
                risk_score += 25
                reasons.append(f"Sensitive file type: {file_extension}")

            if file_extension in ARCHIVE_TYPES:
                risk_score += 20
                reasons.append(f"Archive/compressed file type detected: {file_extension}")

            for keyword in SENSITIVE_KEYWORDS:
                if keyword in filename_lower:
                    risk_score += 35
                    reasons.append(f"Sensitive keyword found in filename: {keyword}")
                    break

            if destination_domain in PERSONAL_DOMAINS:
                risk_score += 40
                reasons.append(f"Upload to personal domain: {destination_domain}")

            if destination_domain not in COMPANY_DOMAINS:
                risk_score += 30
                reasons.append(f"External destination: {destination_domain}")

            if department in HIGH_RISK_DEPARTMENTS:
                risk_score += 20
                reasons.append(f"High-risk department: {department}")

            if employment_status in HIGH_RISK_EMPLOYMENT_STATUS:
                risk_score += 50
                reasons.append(f"Employment status risk: {employment_status}")

            if classification == "Confidential":
                risk_score += 35
                reasons.append("Confidential file classification")

            elif classification == "Restricted":
                risk_score += 50
                reasons.append("Restricted file classification")

            if file_count >= BULK_FILE_COUNT:
                risk_score += 30
                reasons.append(f"Bulk file movement detected: {file_count} files")

            if upload_count[user] >= UPLOAD_THRESHOLD:
                risk_score += 25
                reasons.append(f"Repeated upload activity by user: {upload_count[user]} uploads")

            try:
                event_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M")
                hour = event_time.hour

                if hour >= AFTER_HOURS_START or hour < AFTER_HOURS_END:
                    risk_score += 20
                    reasons.append("Upload occurred after business hours")

            except ValueError:
                reasons.append("Timestamp format could not be checked")

        risk_score = min(risk_score, 100)

        if risk_score > 0:
            alerts.append({
                "severity": get_severity(risk_score),
                "risk_score": risk_score,
                "timestamp": timestamp,
                "user": user,
                "department": department,
                "employment_status": employment_status,
                "filename": filename,
                "file_size_mb": file_size_mb,
                "file_count": file_count,
                "classification": classification,
                "destination": destination,
                "action": action,
                "reasons": reasons
            })

with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
    report.write("===== Mini DLP Alert Report =====\n")
    report.write(f"Generated: {datetime.now()}\n\n")

    if not alerts:
        report.write("No DLP concerns detected.\n")
    else:
        for alert in alerts:
            report.write(f"Severity: {alert['severity']}\n")
            report.write(f"Risk Score: {alert['risk_score']}/100\n")
            report.write(f"Time: {alert['timestamp']}\n")
            report.write(f"User: {alert['user']}\n")
            report.write(f"Department: {alert['department']}\n")
            report.write(f"Employment Status: {alert['employment_status']}\n")
            report.write(f"File: {alert['filename']}\n")
            report.write(f"File Size: {alert['file_size_mb']} MB\n")
            report.write(f"File Count: {alert['file_count']}\n")
            report.write(f"Classification: {alert['classification']}\n")
            report.write(f"Destination: {alert['destination']}\n")
            report.write(f"Action: {alert['action']}\n")
            report.write("Reasons:\n")

            for reason in alert["reasons"]:
                report.write(f"- {reason}\n")

            report.write("Analyst Response Actions:\n")

            if alert["severity"] == "High":
                report.write("- Block or restrict the data transfer if still in progress.\n")
                report.write("- Identify data sensitivity and confirm whether a policy violation occurred.\n")
                report.write("- Investigate user activity, intent, and business justification.\n")
                report.write("- Review additional user activity for potential data exfiltration patterns.\n")
                report.write("- Preserve relevant evidence and initiate incident response procedures if unauthorized transfer is confirmed.\n")

            elif alert["severity"] == "Medium":
                report.write("- Review the transfer and validate whether it aligns with business need and company policy.\n")
                report.write("- Confirm the destination is approved for the type of data involved.\n")
                report.write("- Check for repeated or unusual transfer behavior from the same user.\n")
                report.write("- Document findings and continue monitoring for escalation.\n")

            else:
                report.write("- Log the activity for visibility.\n")
                report.write("- Continue monitoring for repeated behavior or additional indicators.\n")
                report.write("- No immediate containment action required unless activity repeats or context changes.\n")

            report.write("-" * 50 + "\n")

print(f"DLP alert report created: {OUTPUT_FILE}")