This project is a real-time log monitoring system written in Python that detects suspicious login activity by analyzing server log files.
It identifies repeated failed login attempts from the same IP address within a short time window and raises alerts to help detect brute-force attacks.

## Features

Real-time monitoring of log files
Detects multiple failed login attempts from a single IP
Configurable alert threshold and time window
Logs security incidents to a separate file
Optional email alert notifications
Prevents alert spamming

## Technologies Used

Python 3.12

Regular Expressions (re)

Logging module

SMTP (for email alerts)

Data structures (defaultdict, deque)



## Configuration

Inside log_monitor.py:

LOG_FILE = "server.log"
INCIDENT_LOG = "incident.log"

ALERT_THRESHOLD = 5    # Number of failed attempts
TIME_WINDOW = 60       # Time window in seconds

ENABLE_EMAIL_ALERTS = False

Email Alerts (Optional)

To enable email alerts:

Set ENABLE_EMAIL_ALERTS = True

Update EMAIL_CONFIG with valid credentials

EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender": "alert@example.com",
    "password": "your_email_password",
    "receiver": "admin@example.com"
}



## How to Run

Ensure Python 3.10+ is installed

Navigate to the project directory:

cd D:\Cognitex_Project


Create the log file (if it doesn’t exist):

New-Item server.log


Run the script:

python log_monitor.py

 Sample Log Entry (server.log)
Failed password for invalid user admin from 192.168.1.50 port 22 ssh2


Add this line 5 times within 60 seconds to trigger an alert.

## Sample Output
Console Output
 Log monitoring started...
ALERT: 5 failed login attempts from IP 192.168.1.50

Incident Log (incident.log)
2025-12-30 14:32:11 - WARNING - ALERT: 5 failed login attempts from IP 192.168.1.50

## How It Works

The script continuously watches server.log

Failed login attempts are detected using regex

Each IP’s attempts are tracked within a time window

If attempts exceed the threshold:

An alert is printed

The incident is logged

Optional email is sent
