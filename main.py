import os
import re
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from bs4 import BeautifulSoup

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def establish_connection():
    """Establish connection to Google API."""
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


def get_emails_by_label(service, email_label: str, search_subject: str) -> list[dict]:
    """Get emails with a specific subject from a label."""
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    label_id = next((label["id"] for label in labels if label["name"] == email_label), None)
    filtered_emails = []
    saved_verbs = set()
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop", "Deutsch_verbs")
    os.makedirs(desktop_path, exist_ok=True)

    for file in os.listdir(desktop_path):
        if file.endswith(".html"):
            saved_verbs.add(file.replace(".html", ""))

    if not label_id:
        print(f'Label "{email_label}" not found.')
        return []

    page_token = None
    while True:
        response = service.users().messages().list(userId="me", labelIds=[label_id], maxResults=100,
                                                   pageToken=page_token).execute()
        messages = response.get("messages", [])
        page_token = response.get("nextPageToken")

        for msg in messages:
            msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
            headers = msg_data["payload"]["headers"]
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")

            if subject.startswith(search_subject):
                body = extract_email_body(msg_data)
                if body:
                    verb = extract_verb(body)
                    if verb is None:
                        verb = extract_verb_using_bs4(body)
                    if verb and verb.replace(" ", "-") not in saved_verbs:
                        print(f'Going ahead with verb "{verb}"')
                        filename = f"{verb.replace(' ', '-').strip()}.html"
                        filtered_emails.append({"filename": filename, "content": body})
                        saved_verbs.add(verb.replace(" ", "-"))

        if not page_token:
            break

    print(f'Found {len(filtered_emails)} new emails matching "{search_subject}".')
    return filtered_emails


def extract_verb_using_bs4(body) -> str:
    """Extracts the full verb phrase from the email body, handling HTML tags."""

    # Parse HTML
    soup = BeautifulSoup(body, "html.parser")

    # Find the paragraph that contains the phrase
    for p in soup.find_all("p"):
        if "Today we'll go through the verb:" in p.get_text():

            # Find all strong tags inside it
            strong_tags = p.find_all("strong")

            # Extract text from all strong tags and join them
            verb_text = " ".join(tag.get_text(strip=True) for tag in strong_tags if tag.get_text(strip=True))

            # Remove leading/trailing colons or extra spaces
            verb_text = re.sub(r"^[\s:]+|[\s:]+$", "", verb_text)

            print("Cleaned Extracted verb:", verb_text)  # Debugging step

            return verb_text if verb_text else None

    return None  # Return None if not found


def extract_email_body(msg_data):
    """Extracts the full HTML body from the email message."""
    payload = msg_data.get("payload", {})

    if "parts" in payload:
        for part in payload["parts"]:
            if part.get("mimeType") == "text/html":
                return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
    elif payload.get("body") and payload["body"].get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")

    return None


def extract_verb(body):
    """Extracts the full verb phrase from the email body."""
    match = re.search(r"Today we'll go through the verb: ([\w\s]+) \(", body)
    return match.group(1).strip() if match else None


def save_emails_to_html(emails):
    """Saves emails to separate HTML files in the Desktop 'deutsch' folder."""
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop", "Deutsch_verbs")
    os.makedirs(desktop_path, exist_ok=True)

    for email in emails:
        filename = os.path.join(desktop_path, email["filename"])
        with open(filename, "w", encoding="utf-8") as file:
            file.write(email['content'])
        print(f"Saved: {filename}")


def main():
    """Fetch and save emails as HTML in Desktop's 'deutsch' folder."""
    try:
        service = build("gmail", "v1", credentials=establish_connection())
        emails = get_emails_by_label(service, email_label="New Deutsch words", search_subject="How’d you say in German:")
        if emails:
            save_emails_to_html(emails)
    except HttpError as error:
        print(f"An error occurred: {error}")


if __name__ == "__main__":
    main()
