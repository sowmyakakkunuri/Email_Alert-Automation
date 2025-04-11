from pydantic import BaseModel, EmailStr, constr
from typing import Optional, Dict, Any
from datetime import datetime

class UserSchema(BaseModel): # type: ignore
    email: EmailStr
    phone_number: Optional[str] = None  
    oauth_credentials: Dict[str, Any]
    alert_system: Optional[bool]
    created_time: datetime  # Timestamp for when the user was created
