from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from uuid import UUID, uuid4

class FeedbackBase(BaseModel):
    """Base model for feedback data"""
    tour_id: UUID = Field(..., description="ID of the tour this feedback belongs to")
    rating: int = Field(..., ge=1, le=5, description="Rating (1-5)")
    comments: Optional[str] = Field(None, description="Comments about the tour")

class FeedbackCreate(FeedbackBase):
    """Model for creating new feedback"""
    pass

class FeedbackUpdate(BaseModel):
    """Model for updating existing feedback"""
    rating: Optional[int] = Field(None, ge=1, le=5)
    comments: Optional[str] = None

class FeedbackInDB(FeedbackBase):
    """Model for feedback data stored in the database"""
    id: UUID = Field(default_factory=uuid4)
    submitted_by: str = Field(..., description="ID of the user who submitted the feedback")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class FeedbackResponse(FeedbackInDB):
    """Model for feedback data returned to the client"""
    pass
