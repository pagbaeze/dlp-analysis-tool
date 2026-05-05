# DLP Analysis Tool (Python)

This project simulates a Data Loss Prevention (DLP) system that detects potential data exfiltration and insider threats based on user behavior and file activity. It analyzes factors such as file sensitivity, upload patterns, destination domains, and time of activity to assign risk scores and generate alerts.

---

## Features

- Detects bulk file uploads and abnormal transfer behavior  
- Flags sensitive file types (.xlsx, .pdf, .zip, etc.)  
- Identifies uploads to personal or unapproved domains (Gmail, iCloud, etc.)  
- Detects after-hours or unusual user activity  
- Applies risk scoring and severity classification (Low / Medium / High)  
- Simulates insider threat detection and alert prioritization  

---

## How to Run

### Option 1 (Windows)
Double click:
run_dlp.bat  

### Option 2 (Command Line)
py mini_dlp_alert.py  

---

## Input

dlp_events.csv  

This file can be modified to simulate different scenarios such as:
- Large data transfers  
- Sensitive file uploads  
- Activity to external or personal domains  

---

## Output

dlp_alert_report.txt  

The report includes:
- Risk score and severity level  
- Detection reasoning  
- User activity details  
- Recommended response actions  

---

## Purpose

This project demonstrates core DLP concepts including data monitoring, insider threat detection, and risk-based alerting. It is designed to reflect how security teams identify and prioritize potential data exfiltration events.
