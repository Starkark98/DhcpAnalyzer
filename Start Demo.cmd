@echo off
rem DHCP Analyzer by Starkark98 - demo with sample data
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "%~dp0DhcpAnalyzer.ps1" -Demo
