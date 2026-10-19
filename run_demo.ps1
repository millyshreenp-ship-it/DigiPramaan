# SUTRAM - One-Command Demo Launcher for Windows PowerShell
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  SUTRAM - AI Forensics & Adversarial Engine Launcher" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Run seed check
python scripts/seed_demo.py

# Launch Full-Stack Server
Write-Host "`nStarting server at http://localhost:8000..." -ForegroundColor Green
Write-Host "Press Ctrl+C to terminate." -ForegroundColor Yellow
python demo.py
