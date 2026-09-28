from typing import List, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.event import Detection
from backend.app.schemas.event import DetectionResponse

router = APIRouter(prefix="/detections", tags=["Detections"])

@router.get("", response_model=List[DetectionResponse])
def list_detections(asset_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Detection)
    if asset_id:
        query = query.filter(Detection.asset_id == asset_id)
    return query.order_by(Detection.created_at.desc()).all()
