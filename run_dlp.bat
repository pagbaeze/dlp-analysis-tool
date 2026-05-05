@echo off
echo ========================================
echo     Running Mini DLP Alert Tool
echo ========================================
echo.

cd /d %~dp0

py mini_dlp_alert.py

echo.
echo Opening DLP report...
start "" dlp_alert_report.txt

echo.
echo Done.
pause