"""Generates a small, internally consistent demo scenario: 'office file copied to USB at ~22:30 IST'.
All three sources describe the same night so Person 2's timeline has real cross-source correlation to show."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import random

OUT = Path(__file__).parent
IST = timezone(timedelta(hours=5, minutes=30))
random.seed(7)

# ---- 1. auth.log (BSD syslog: no year, no tz) -- written in the server's local time (IST) ----
def s(t): return t.strftime("%b %e %H:%M:%S")
base = datetime(2026, 3, 14, 22, 0, 0)
L = lambda dt, host, proc, msg: f"{s(dt)} {host} {proc}: {msg}"
auth = [
    L(base + timedelta(minutes=0, seconds=12), "fin-ws-07", "CRON[2211]", "(root) CMD (/usr/local/bin/nightly_backup.sh)"),
    L(base + timedelta(minutes=3, seconds=40), "fin-ws-07", "sshd[2290]", "Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2"),
    L(base + timedelta(minutes=3, seconds=44), "fin-ws-07", "sshd[2290]", "Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2"),
    L(base + timedelta(minutes=9, seconds=2),  "fin-ws-07", "sshd[2344]", "Accepted password for rahul from 10.20.1.15 port 49821 ssh2"),
    L(base + timedelta(minutes=9, seconds=3),  "fin-ws-07", "sshd[2344]", "pam_unix(sshd:session): session opened for user rahul by (uid=0)"),
    L(base + timedelta(minutes=28, seconds=51), "fin-ws-07", "kernel", "[ 8123.1] usb 1-1: New USB device found, idVendor=0781, idProduct=5567"),
    L(base + timedelta(minutes=28, seconds=51), "fin-ws-07", "kernel", "[ 8123.2] usb 1-1: Product: Cruzer Blade"),
    L(base + timedelta(minutes=28, seconds=51), "fin-ws-07", "kernel", "[ 8123.3] usb 1-1: SerialNumber: 4C530001230917115371"),
    L(base + timedelta(minutes=28, seconds=53), "fin-ws-07", "kernel", "[ 8125.0] sd 6:0:0:0: [sdb] Attached SCSI removable disk"),
    L(base + timedelta(minutes=31, seconds=5), "fin-ws-07", "sudo", "   rahul : TTY=pts/0 ; PWD=/home/rahul ; USER=root ; COMMAND=/bin/cp /srv/finance/Q4_payroll.xlsx /media/usb/"),
    L(base + timedelta(minutes=33, seconds=20), "fin-ws-07", "sshd[2344]", "pam_unix(sshd:session): session closed for user rahul"),
    "this line is deliberately malformed to demonstrate skipped-line reporting",
]
(OUT / "auth.log").write_text("\n".join(auth) + "\n")

# ---- 2. web access log (explicit +0530 offset: exact) ----
def a(dt, ip, method, path, status, size, ua="Mozilla/5.0"):
    return f'{ip} - - [{dt.replace(tzinfo=IST).strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
w = datetime(2026, 3, 14, 22, 5, 0)
acc = [
    a(w, "10.20.1.15", "GET", "/portal/login", 200, 1532),
    a(w + timedelta(minutes=1), "10.20.1.15", "POST", "/portal/login", 302, 0),
    a(w + timedelta(minutes=14, seconds=5), "10.20.1.15", "GET", "/portal/finance/Q4_payroll.xlsx", 200, 48213),
    a(w + timedelta(minutes=15), "198.51.100.9", "GET", "/../../etc/passwd", 404, 196, "curl/8.4.0"),
    a(w + timedelta(minutes=16), "198.51.100.9", "GET", "/portal/admin", 403, 210, "curl/8.4.0"),
]
(OUT / "access.log").write_text("\n".join(acc) + "\n")

# ---- 3. TSK body file (epoch UTC) ----
def ep(dt): return int(dt.replace(tzinfo=IST).timestamp())
t = datetime(2026, 3, 14, 22, 28, 0)
body = [
    f"0|/srv/finance/Q4_payroll.xlsx|48211|r/rrw-r--r--|1001|1001|48213|{ep(t+timedelta(minutes=2, seconds=58))}|{ep(datetime(2026,3,10,16,40))}|{ep(datetime(2026,3,10,16,40))}|{ep(datetime(2026,3,10,16,40))}",
    f"0|/media/usb/Q4_payroll.xlsx|12|r/rrw-r--r--|1001|1001|48213|{ep(t+timedelta(minutes=3, seconds=6))}|{ep(t+timedelta(minutes=3, seconds=6))}|{ep(t+timedelta(minutes=3, seconds=6))}|{ep(t+timedelta(minutes=3, seconds=6))}",
    f"0|/var/log/auth.log|90210|r/rrw-r-----|0|4|2411|{ep(t+timedelta(minutes=6))}|{ep(t+timedelta(minutes=5, seconds=20))}|{ep(t+timedelta(minutes=5, seconds=20))}|{ep(datetime(2026,1,2,9,0))}",
]
(OUT / "fs.body").write_text("\n".join(body) + "\n")
print("wrote auth.log, access.log, fs.body")
