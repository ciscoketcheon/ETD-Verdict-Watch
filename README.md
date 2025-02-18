# ETD Event Monitoring Script

This repository contains a Python script to monitor email events using Cisco's ETD API and notify an administrator of detected events via email.

## Features

- Queries Cisco ETD API for email events.
- Filters events based on specified verdicts and techniques.
- Sends email notifications to an administrator if matching events are detected.
- Configurable to allow custom verdicts, techniques, and email settings.

## Prerequisites

- Python 3.x
- Access to Cisco ETD API with valid credentials.
- SMTP server details for sending emails.

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/etd-monitoring-script.git
   cd etd-monitoring-script

2. **Install required packages:**

   Ensure you have requests and smtplib installed. You can install requests using pip:
   ```bash
   pip install requests

## Configuration

   Edit the script to configure the following variables:

   **API and Email Settings:**
        TOKEN_URL, SEARCH_URL, API_KEY, CLIENT_ID, CLIENT_SECRET
        SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ADMIN_EMAIL

   **Monitored Mailboxes:**
        MONITORED_MAILBOXES: List of mailboxes to monitor.

   **Filtering Criteria:**
        VERDICT_VARIABLE: Verdict to match, leave empty to match all.
        TECHNIQUE_VARIABLE: Technique to match, leave empty to match all.

## Usage

   **Run the Script:**
   Execute the script to start monitoring:
   ```bash
   python etd_monitoring_script.py


   **Schedule with Crontab (Optional):**
   You can schedule the script to run periodically using crontab. For example, to run every hour, add the following line to your crontab:
   ```bash
   0 * * * * /usr/bin/python3 /path/to/etd_verdict_watch.py


##How It Works

    API Query: The script queries the Cisco ETD API for email events within the last hour.

    Event Filtering: Events are filtered based on user-defined verdicts and techniques.

    Email Notification: If matching events are found, an email is sent to the administrator with details of the events.

    Customization: The script's behavior can be customized by adjusting the user-configurable variables at the top of the script.

##License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

