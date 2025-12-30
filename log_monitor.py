import time
import re
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
import smtplib
from email.message import EmailMessage


LOG_FILE = "server.log"
INCIDENT_LOG = "incident.log"

FAILED_LOGIN_PATTERN = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
ALERT_THRESHOLD = 5           # Failed attempts
TIME_WINDOW = 60              # Seconds

ENABLE_EMAIL_ALERTS = False   # Set True to enable email alerts

EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender": "alert@example.com",
    "password": "your_email_password",
    "receiver": "admin@example.com"
}

logging.basicConfig(
    filename=INCIDENT_LOG,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

failed_attempts = defaultdict(lambda: deque())

def send_email_alert(ip, count):
    msg = EmailMessage()
    msg["Subject"] = "SECURITY ALERT: Suspicious Login Activity"
    msg["From"] = EMAIL_CONFIG["sender"]
    msg["To"] = EMAIL_CONFIG["receiver"]
    msg.set_content(
        f"Suspicious activity detected!\n\n"
        f"IP Address: {ip}\n"
        f"Failed Login Attempts: {count}\n"
        f"Time: {datetime.now()}"
    )

    with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
        server.starttls()
        server.login(EMAIL_CONFIG["sender"], EMAIL_CONFIG["password"])
        server.send_message(msg)

def alert(ip, count):
    message = f"ALERT: {count} failed login attempts from IP {ip}"
    print(message)
    logging.warning(message)

    if ENABLE_EMAIL_ALERTS:
        send_email_alert(ip, count)

def process_log_line(line):
    match = FAILED_LOGIN_PATTERN.search(line)
    if match:
        ip = match.group(1)
        now = datetime.now()

        attempts = failed_attempts[ip]
        attempts.append(now)

        # Remove old attempts
        while attempts and (now - attempts[0]).seconds > TIME_WINDOW:
            attempts.popleft()

        if len(attempts) >= ALERT_THRESHOLD:
            alert(ip, len(attempts))
            attempts.clear()  # Prevent alert spam

def monitor_log():
    print("[*] Log monitoring started...")
    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)  # Move to end of file

        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue
            process_log_line(line)

if __name__ == "__main__":
    try:
        monitor_log()
    except KeyboardInterrupt:
        print("\n[!] Log monitoring stopped.")

