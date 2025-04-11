from datetime import datetime, timezone
from email.utils import parseaddr
from http.client import HTTPException
from fastapi.responses import JSONResponse
from flask import Flask, flash, json, render_template, request, jsonify, redirect, url_for, session
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pymongo import MongoClient
import os
import base64
import re
from pydantic import EmailStr, ValidationError
from dotenv import load_dotenv
from responses import generate_email_reply, get_email_summary
from deadline import start_fetching_deadline
from models.user_schema import UserSchema  # Import schema for validation

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Google OAuth setup
CLIENT_SECRETS_FILE = 'credentials3.json'
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

# MongoDB setup
client = MongoClient(os.getenv("MONGODB_KEY"))  # Replace with your MongoDB connection string
db = client.user_data  # MongoDB database
users_collection = db.users  # Collection for storing user information
emails_collection = db.emails


# Allow insecure transport for OAuth
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Utility function to convert credentials to dictionary
def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

@app.route('/')
def index():
    # Check if user is logged in
    return render_template('login.html')

@app.route('/home')
def home():
    email = request.args.get('email')
    # Check if user is logged in
    user=users_collection.find_one({'email': email})
    if  not user:
        return redirect(url_for('login'))

    # Render the home page with navigation
    return render_template('home.html', email=user['email'])


@app.route('/logout')
def logout():
    session.pop('credentials', None)
    return redirect(url_for('home'))


@app.route('/login')
def login():
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080/callback'
    )
    authorization_url, state = flow.authorization_url(access_type='offline')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080/callback'
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    session['credentials'] = credentials_to_dict(credentials)
    # Get user info and store in the database
     
    user_info = user_service.userinfo().get().execute()

    email_user=user_info['email']
    existing_user = users_collection.find_one({'email': user_info['email']})
    # print(session.get('credentials'))

    if not existing_user: 
        # Insert the full credentials if it's a new user
        user_data = {
            'email': user_info['email'],
            'oauth_credentials': credentials_to_dict(credentials),
            'created_time': datetime.now(timezone.utc),
            'alert_system': False  # Default or required value
        }

        # Insert the new user into the database
        users_collection.update_one(
            {'email': user_info['email']},
            {'$set': dict(user_data)},
            upsert=True
        )

    if credentials.token: 
        users_collection.update_one(
            {'email': user_info['email']},
            {'$set': {'oauth_credentials.token': credentials.token}},
            upsert=False  # Ensure we only update existing documents
        )
    # existing_user = users_collection.find_one({'email': emaid_user})
    
    # Proceed to the email reading page after updating the access token
    return redirect(url_for('home', email=email_user))


@app.route('/alert_system', methods=['GET', 'POST'])
def alert_system():
    email = request.args.get('email')
    # print(email)
    if not email:
        return redirect(url_for('login'))

    user_data = users_collection.find_one({'email': email})
    if not user_data:
        return redirect(url_for('login'))  # Redirect if user data is not found
    
    print(request.method,request.form.get('phone'))
    if request.method == 'POST' :
        phone_number = request.form.get('phone')
        print(phone_number)
        if phone_number == '':
            flash('Please enter a phone number.', 'error')
            return redirect(url_for('alert_system', email=email))
        users_collection.update_one(
            {'email': email},
            {'$set': {'phone_number': phone_number,'alert_system': True}},
            upsert=False
        )
        flash('Profile updated successfully.', 'success')

        return redirect(url_for('alert_system', email=email))

    return render_template('alert_system.html', user=user_data)


@app.route('/disable-alert/<email>', methods=['POST'])
def disable_alert(email):
    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if not user.get('alert_system', True):
        return jsonify({"message": "Alert system is already disabled."}), 200
    
    # Disable the alert system
    users_collection.update_one(
        {'email': email},
        {'$set': {'alert_system': False}},
        upsert=False
    )
    
    return jsonify({"message": "Alert system has been disabled successfully."}), 200



@app.route('/send_email', methods=['POST'])
def send_email():
    try:
        # print("Step 1: Received Request")
        data = request.json

        user = parseaddr(data.get('user'))[1]  # Extract email address from the user field
        if not user or "@" not in user:
            raise ValueError(f"Invalid user email: {user}")

        recipient = parseaddr(data.get('recipient'))[1]  # Extract email address from the recipient field
        if not recipient or "@" not in recipient:
            raise ValueError(f"Invalid recipient email: {recipient}")

        content = data.get('content')
        print(recipient,"\n",user)
        if not (recipient and user and content):
            raise ValueError("Missing required fields: recipient, user, or content.")

        # Retrieve user credentials from the database
        user_data = users_collection.find_one({"email": user})
        # print(user_data)
        # print("///----------")
        # print(user_data['oauth_credentials'])
        if not user_data or user_data==None:
            raise Exception(f"No user found with email {user}. Please authenticate first.")
        
        if not user_data or 'oauth_credentials' not in user_data:
            raise Exception("User is not authenticated or credentials are missing.")

        # Load credentials from the user's stored OAuth credentials
        credentials_dict = user_data['oauth_credentials']
        credentials = Credentials.from_authorized_user_info(credentials_dict)

        # Check if 'gmail.send' scope is included
        

        # Build the Gmail API service
        service = build('gmail', 'v1', credentials=credentials)
        print(user_data['oauth_credentials'])

        # Create the email message
        email_message = f"From: me\nTo: {recipient}\nSubject: Reply from {user}\n\n{content}"
        raw_message = base64.urlsafe_b64encode(email_message.encode('utf-8')).decode('utf-8')

        message = {'raw': raw_message}

        # Send the email
        service.users().messages().send(userId='me', body=message).execute()

        print("Step 5: Email sent successfully")
        return jsonify({"success": True, "message": "Email sent successfully."})

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"success": False, "error": str(e)})


@app.route('/read_emails')
def read_emails():
    credentials = session.get('credentials')
    # print("session : ",session)


    if not credentials:
        return jsonify({'error': 'Token not found, please login again.'}), 401

    credentials = Credentials(**credentials)
    service = build('gmail', 'v1', credentials=credentials)
    results = service.users().messages().list(userId='me', maxResults=9, labelIds=['INBOX']).execute()

    messages = results.get('messages', [])
    email_list = []
    receipent=""

    if messages:
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            payload = msg['payload']
            headers = payload.get('headers', [])
            body = ""

            if 'parts' in payload:  # Handle multipart messages
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = part['body']['data']
                        break
            else:
                body = payload['body']['data']

            body = base64.urlsafe_b64decode(body).decode('utf-8')
            body = re.sub(r'http\S+', '', body)  # Remove URLs
            subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')
            from_address = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown')
            to_address = next((header['value'] for header in headers if header['name'] == 'To'), 'Unknown')
            date_recieved = next((header['value'] for header in headers if header['name'] == 'Date'), 'Unknown')
            receipent=to_address
            is_unread = 'UNREAD' in msg.get('labelIds', [])
            email_data = {
                'email_id': message['id'],
                'user_email': session.get('user_email'),  # Use user email from session
                'subject': subject,
                'body': body,
                'snippet': msg['snippet'],
                'from': from_address,
                'to': to_address,
                'date': date_recieved,
                'received_time': datetime.now(timezone.utc),
                'is_unread': is_unread
                  # Save the current timestamp
            }
            email_list.append(email_data)

            # Upsert email data into MongoDB
            emails_collection.update_one(
                {'email_id': email_data['email_id']},
                {'$set': email_data},
                upsert=True
            )
    print(receipent)
        
    return render_template('emails.html', emails=email_list, user_email=receipent.strip('<>'))



@app.route('/email_content/<string:email_id>', methods=['GET'])
def email_content(email_id):
    # Retrieve the email from MongoDB
    email = emails_collection.find_one({'email_id': email_id})
    if not email:
        return jsonify({'error': 'Email not found'}), 404

    return render_template('email_content.html', email=email)


@app.route('/auto_reply/<string:email_id>', methods=['POST'])
def auto_reply(email_id):
    email = emails_collection.find_one({'email_id': email_id})
    if not email:
        return jsonify({'error': 'Email not found'}), 404

    reply = generate_email_reply(email)
    return render_template('email_content.html', email=email, reply=reply)


@app.route('/email_summarizer/<string:email_id>', methods=['POST'])
def email_summarizer(email_id):
    email = emails_collection.find_one({'email_id': email_id})
    if not email:
        return jsonify({'error': 'Email not found'}), 404

    summary = get_email_summary(email)
    return render_template('email_content.html', email=email, summary=summary)





@app.route('/user_info')
def user_info():
    """Fetch and display user's profile and email information."""
    credentials = session.get('credentials')
    if not credentials:
        return jsonify({'error': 'Token not found, please login again.'}), 401

    credentials = Credentials(**credentials)
    service = build('oauth2', 'v2', credentials=credentials)

    user_info = service.userinfo().get().execute()
    return jsonify(user_info)

if __name__ == '__main__':
    app.run(debug=True, port=8080)
