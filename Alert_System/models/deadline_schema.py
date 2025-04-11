from pydantic import BaseModel, EmailStr, constr
from typing import Optional, Dict, Any
from datetime import datetime

class DeadlineSchema(BaseModel): 
    userEmail: Optional[str]
    emailFrom: Optional[str]
    body: Optional[str]
    deadline: Optional[datetime]
    reminder: Optional[datetime]

    # class Config:
    #     orm_mode = True  # Makes it compatible with ORM models
