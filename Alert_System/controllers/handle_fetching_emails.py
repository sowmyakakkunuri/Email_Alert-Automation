import base64
import datetime
import os
import re
from flask import jsonify
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from pydantic import ValidationError
from pymongo import MongoClient
from models.deadline_schema import DeadlineSchema

from controllers.handle_deadlines import fetch_deadline

client = MongoClient(os.getenv("MONGODB_KEY"))  # Replace with your MongoDB connection string (MONGODB_KEY)
db = client.user_data  # MongoDB database
users_collection = db.users

deadline_collection = db.deadlines


# List of phrases indicating no deadlines
NO_DEADLINE_PHRASES = [
    "no deadlines",
    "none",
    "none.",
    "no deadline found",
    "no due date",
    "not applicable",
    "None",
    "None.",
    "No deadline",
    "No due date",
    "Not applicable",
    "No deadlines",
    "No deadlines found",
    "No due dates",
    "No due dates found",
    "No deadlines or due dates",
    "None/"
]

# def fetch_emails():
#     # for user in users_collection.find({}):
        

#     user = users_collection.find_one({'email': '21bd1a662qcsmb@gmail.com'})

#     refresh_token = user['oauth_credentials']['refresh_token']
#     access_token = user['oauth_credentials']['token']
#     client_id = user['oauth_credentials']['client_id']
#     client_secret = user['oauth_credentials']['client_secret']

#     # Load credentials using access and refresh tokens
#     credentials = Credentials(
#         token=access_token,
#         refresh_token=refresh_token,
#         client_id=client_id,
#         client_secret=client_secret,
#         token_uri="https://oauth2.googleapis.com/token",
#     )

#     # Refresh the token if it has expired
#     if credentials.expired and credentials.refresh_token:
#         credentials.refresh(Request())
#         # Save updated access_token and refresh_token to your database
#         access_token = credentials.token
#         refresh_token = credentials.refresh_token

#     emails = read_emails(credentials,user)    
#     return emails

def fetch_emails():
    print("Fetching emails...")
    # Iterate through all users in the database
    for user in users_collection.find({}):
        email = user['email']  # Extract user's email
        print(f"Processing emails for user: {email}")

        # Extract OAuth credentials for the user
        refresh_token = user['oauth_credentials'].get('refresh_token')
        access_token = user['oauth_credentials'].get('token')
        client_id = user['oauth_credentials'].get('client_id')
        client_secret = user['oauth_credentials'].get('client_secret')

        if not (refresh_token and access_token and client_id and client_secret):
            print(f"Skipping user {email} due to incomplete credentials.")
            continue

        # Load credentials using access and refresh tokens
        credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            client_id=client_id,
            client_secret=client_secret,
            token_uri="https://oauth2.googleapis.com/token",
        )

        # Refresh the token if it has expired
        if credentials.expired and credentials.refresh_token:
            try:
                credentials.refresh(Request())
                # Save updated access_token and refresh_token to the database
                users_collection.update_one(
                    {'email': email},
                    {'$set': {
                        'oauth_credentials.token': credentials.token,
                        'oauth_credentials.refresh_token': credentials.refresh_token
                    }}
                )
            except Exception as e:
                print(f"Failed to refresh token for user {email}: {e}")
                continue

        # Fetch emails for the user
        try:
            emails, senders_list = read_emails(credentials, user)
            print(f"Fetched {len(emails)} emails for user {email}.")
            print(emails)
            print("--------------------------------")
        except Exception as e:
            print(f"Error fetching emails for user {email}: {e}")

    return "Email fetching completed."




def extract_deadline_and_reminder(llm_response):
    # Regex pattern to match the date in DD-MM-YYYY format
    date_pattern = r'\d{2}-\d{2}-\d{4}'
    
    # Search for the date in the response
    date_match = re.search(date_pattern, llm_response)
    
    if date_match:
        # Extract the date from the matched string
        deadline_date = datetime.datetime.strptime(date_match.group(), "%d-%m-%Y")
        
        # Calculate reminder date (one day before deadline)
        reminder_date = deadline_date - datetime.timedelta(days=1)
        
        # Return the extracted deadline and reminder date
        return deadline_date, reminder_date
    
    return None, None


def extract_name_and_email(input_str):
    # Regex pattern to capture name and email
    match = re.match(r'(.*)<(.*)>', input_str)
    if match:
        name = match.group(1).strip()
        email = match.group(2).strip()
        return name, email
    return "Unknown", input_str.strip()

def update_db(user,deadline,sender_info):
    print(user,sender_info)
    print("------------------")
    dealine_body = deadline
    dealine_date,reminder = extract_deadline_and_reminder(deadline)
    userName, userEmail = extract_name_and_email(user)
    senderName,senderEmail = extract_name_and_email(sender_info)
    deadline_schema = DeadlineSchema(userEmail=userEmail,emailFrom=senderEmail, body=dealine_body, deadline=dealine_date, reminder=reminder)
    try:
        result = deadline_collection.insert_one(dict(deadline_schema))
        
    except ValidationError as e:
        print(e)

    

def read_emails(credentials, user):
    # Build Gmail API service
    service = build('gmail', 'v1', credentials=credentials)

    now = datetime.datetime.now(datetime.timezone.utc)
    six_hours_ago = now - datetime.timedelta(hours=6)
    timestamp = int(six_hours_ago.timestamp())

    # Use the `q` parameter to filter emails
    query = f"after:{timestamp}"

    results = service.users().messages().list(userId='me', maxResults=6, q=query, labelIds=['INBOX']).execute()
    messages = results.get('messages', [])
    email_list = []
    sender_info_list = []

    if messages:
        for i, message in enumerate(messages):
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            payload = msg['payload']
            headers = payload.get('headers', [])
            
            sender_info = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown')
            user_email = next((header['value'] for header in headers if header['name'] == 'To'), 'Unknown')
            
            if sender_info:
                sender_info_list.append(sender_info)

            body = ""
            if 'parts' in payload:  # Handle multipart messages
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = part['body']['data']
                        break
            else:
                body = payload['body']['data']
            
            # Decode and clean up the email body
            body = base64.urlsafe_b64decode(body).decode('utf-8')
            body = re.sub(r'http\S+', '', body)  # Remove URLs
            
            subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')

            email_list.append({
                'id': message['id'],
                'subject': subject,
                'body': body,
                'snippet': msg['snippet']
            })

            # Simulated emails with deadlines
            # if i == 0:  # Override for testing
            #     email_list[0] = {
            #         'id': 4,
            #         'subject': "Hackathon at KMIT College",
            #         'body': "Hello, you are a registered contestant for the hackathon. Pay the registration fee by 9-12-2024.",
            #         'snippet': 'hackathon'
            #     }
            # if i == 3:  # Override for testing
            #     email_list[3] = {
            #         'id': 2,
            #         'subject': "Interview at KMIT College",
            #         'body': "Hello, you are shortlisted for the interview on 9-12-2024 at 10:00 AM.",
            #         'snippet': 'interview'
            #     }

            # Fetch and process deadline
            deadline = fetch_deadline(email_list[i])
            if deadline and not any(phrase in deadline.lower() for phrase in NO_DEADLINE_PHRASES):
                update_db(user_email, deadline, sender_info)  # Pass user email, deadline, and sender info

    return email_list, sender_info_list