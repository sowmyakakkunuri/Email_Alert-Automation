
from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pymongo import MongoClient
# from deadline import start_fetching_deadline

from datetime import datetime, timezone
import os

from pydantic import ValidationError
from controllers.handle_fetching_emails import fetch_emails
from alert import send_alerts

# Flask app setup
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MongoDB setup
client = MongoClient(os.getenv("MONGODB_KEY"))  # Replace with your MongoDB connection string (MONGODB_KEY)
db = client.user_data  # MongoDB database
users_collection = db.users  # Collection for storing user information


@app.route('/')
def home():
    # for user in users_collection.find({}):
        
    emails= fetch_emails()
    send_alerts()
    # return jsonify(emails)

    # deadline_emails = fetch_deadlines()
    return jsonify(emails)




# def get_credentials_from_db(email):
#     user = users_collection.find_one({'email': email})
#     if user and 'oauth_credentials' in user:
#         return Credentials.from_authorized_user_info(user['oauth_credentials'])
#     return None



if __name__ == '__main__':
    # parse_users()
    app.run(debug=True, port=8081)  # Port should match redirect URI