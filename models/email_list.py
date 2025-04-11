from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class EmailSchema(BaseModel):
    email_id: str = Field(..., description="Unique identifier for the email")
    user_email: str = Field(..., description="The email address of the authenticated user")
    subject: Optional[str] = Field(default="No Subject", description="Subject of the email")
    body: str = Field(..., description="Full body of the email")
    snippet: Optional[str] = Field(default="", description="Short snippet or summary of the email")
    received_time: datetime = Field(..., description="Timestamp of when the email was received")
    is_unread: Optional[bool] = Field(..., description="Indicates whether the email is unread or not")
