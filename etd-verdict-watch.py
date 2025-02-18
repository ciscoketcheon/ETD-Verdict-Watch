import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
from requests.auth import HTTPBasicAuth
import json
from datetime import datetime, timedelta


# Constants for the API
TOKEN_URL = 'https://api.xxxxxx.etd.cisco.com/v1/oauth/token'
SEARCH_URL = 'https://api.xxxxxx.etd.cisco.com/v1/messages/search'
# Define the API key
API_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxx'
CLIENT_ID = 'xxxxxxxx-xxxxxxx-xxxxxxxxxxx'
CLIENT_SECRET = 'xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxx'
SMTP_SERVER = 'x.x.x.x'  # Replace with your SMTP server
SMTP_PORT = 25  # Commonly used port for SMTP
SMTP_USER = 'xxxxx@xxxxxx.xxx'  # Replace with your email address
SMTP_PASSWORD = 'xxxxxxxxx'  # Replace with your email password
ADMIN_EMAIL = 'admin@xxxxx.xxx'  # Administrator's email address

# List of monitored mailboxes
MONITORED_MAILBOXES = ['vip@xxxxx.xxx', 'boss@xxxxx.xxx']  # Replace with actual mailboxes


# User-configurable variables for verdicts and techniques
VERDICT_VARIABLE = ""  # Verdict to match; leave empty to match all, e.g. "BEC"
TECHNIQUE_VARIABLE = ""  # Technique to match; leave empty to match all, e.g. "User Impersonation"


def get_access_token():
    token_headers = {
        'x-api-key': API_KEY
    }
    response = requests.post(TOKEN_URL, headers=token_headers, auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET))
    if response.status_code == 200:
        token_data = response.json()
        return token_data['accessToken']
    else:
        print("Failed to obtain access token")
        print(response.status_code)
        print(response.json())
        return None

def query_etd_api(access_token):
    current_time = datetime.utcnow()
    # Look for data in last 1 hour
    past_time = current_time - timedelta(minutes=60)
    
    # Adjust for -5min, ETD API throw error if the time is too near or beyond current time
    adjusted_current_time = current_time - timedelta(minutes=5)
    adjusted_past_time = past_time - timedelta(minutes=5)

    current_time_str = adjusted_current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    past_time_str = adjusted_past_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    search_headers = {
        'Authorization': f'Bearer {access_token}',
        'x-api-key': API_KEY,
        'Content-Type': 'application/json'
    }
    payload = {
        "timestamp": [past_time_str, current_time_str],
        "verdicts": ["bec", "scam", "phishing", "malicious"]
    }
    response = requests.post(SEARCH_URL, headers=search_headers, json=payload)
    
    if response.status_code == 200:
        try:
            data = response.json()
            print("Raw API Response:")
            print(json.dumps(data, indent=4))  # Print the raw JSON data
            return data
        except json.JSONDecodeError:
            print("Error decoding JSON response")
            return None
    else:
        print("Failed to retrieve data")
        print(response.status_code)
        print(response.text)
        return None


def filter_and_group_events(events):
    grouped_events = {}
    
    monitored_mailboxes_lower = [mailbox.lower() for mailbox in MONITORED_MAILBOXES]
    
    messages = events.get('data', {}).get('messages', [])
    
    for event in messages:
        verdict = event.get('verdict', {})
        techniques = verdict.get('techniques', [])
        mailboxes = [mailbox.lower() for mailbox in event.get('mailboxes', [])]

        for mailbox in mailboxes:
            if mailbox in monitored_mailboxes_lower:
                # Convert to lowercase for case-insensitive matching
                event_verdict = verdict.get('category', '').lower()
                event_techniques = [t['type'].lower() for t in techniques]

                # Debug print statements
                print(f"Checking event for mailbox: {mailbox}")
                print(f"Event Verdict: {event_verdict}, Event Techniques: {event_techniques}")

                # Match all if VERDICT_VARIABLE is empty, otherwise match specific (case-insensitive)
                verdict_match = not VERDICT_VARIABLE or event_verdict == VERDICT_VARIABLE.lower()
                # Match all if TECHNIQUE_VARIABLE is empty, otherwise match specific (case-insensitive)
                technique_match = not TECHNIQUE_VARIABLE or any(t == TECHNIQUE_VARIABLE.lower() for t in event_techniques)
                
                # Use OR logic for matching
                if verdict_match or technique_match:
                    print(f"Match found for mailbox: {mailbox}")
                    email_info = {
                        'subject': event.get('subject', 'No Subject'),
                        'messageID': event.get('internetMessageId', 'No Message ID'),
                        'timestamp': event.get('timestamp', 'No Timestamp'),
                        'eventVerdict': event_verdict,
                        'eventTechniques': event_techniques
                    }
                    if mailbox not in grouped_events:
                        grouped_events[mailbox] = []
                    grouped_events[mailbox].append(email_info)
    
    return grouped_events


def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = ADMIN_EMAIL
    msg['Subject'] = subject

    intro_text = "Hi Administrator, these are the detected events for the past 1 hour:\n\n"

    # Combine the intro text with the body
    full_body = intro_text + body

    msg.attach(MIMEText(full_body, 'plain'))
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

def main():
    access_token = get_access_token()
    if access_token:
        events = query_etd_api(access_token)
        if events:
            grouped_events = filter_and_group_events(events)
            if grouped_events:
                subject = "Alert: Matched Events Detected"
                body = json.dumps(grouped_events, indent=4)
                send_email(subject, body)

if __name__ == "__main__":
    main()
