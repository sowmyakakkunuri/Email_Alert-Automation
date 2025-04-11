
import datetime
import os
from pydantic import ValidationError
from pymongo import MongoClient
from twilio.rest import Client
import datetime,os
from dotenv import load_dotenv

load_dotenv()

client = MongoClient(os.getenv("MONGODB_KEY"))  # Replace with your MongoDB connection string (MONGODB_KEY)
db = client.user_data  # MongoDB database
users_collection = db.users
deadline_collection = db.deadlines


ACCOUNT_SID = os.getenv("ACCOUNT_SID_TWILIO")
AUTH_TOKEN = os.getenv("AUTH_TOKEN_TWILIO")

today = datetime.datetime.now()
print(today)


client = Client(ACCOUNT_SID, AUTH_TOKEN)

# message = client.messages.create(
#     from_= '+17756185250',
#     body="Hello from Python Twilio demo!",
#     to='+917207822670'
# )
def send_alerts():
    for user in users_collection.find():
        to_phone_number = user['phone_number']
        if not to_phone_number or user['alert_system']==False:
            continue
        for deadline in deadline_collection.find({'userEmail':user['email']}):
            print(deadline['reminder'])
            print(user )
            if deadline['reminder'] and deadline['reminder'] <= today:
                print("Sending message")
                message = client.messages.create(
                    from_= '+12185000399',
                    body=f'FromEmail:{deadline["emailFrom"]}\nBody:{deadline["body"]}',
                    
                    to=f'+91{to_phone_number}'
                )
            # else:
                
