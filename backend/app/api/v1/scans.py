from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db, SessionLocal
from backend.app.models.asset import Asset
from backend.app.models.scan import Scan
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.scanner.engine import ScannerEngine

router = APIRouter(prefix="/scans", tags=["Scans"])

def _execute_scan_in_background(asset_id: str, scan_id: str, scan_type: str):
    db = SessionLocal()
    try:
        engine = ScannerEngine(db)
        engine.run_scan(asset_id=asset_id, scan_id=scan_id, scan_type=scan_type)
    finally:
        db.close()

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def trigger_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == payload.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Run scan synchronously or background based on request
    engine = ScannerEngine(db)
    scan = engine.run_scan(asset_id=payload.asset_id, scan_type=payload.scan_type)
    return scan

@router.get("", response_model=List[ScanResponse])
def list_scans(asset_id: str = None, db: Session = Depends(get_db)):
    query = db.query(Scan)
    if asset_id:
        query = query.filter(Scan.asset_id == asset_id)
    return query.order_by(Scan.created_at.desc()).all()

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
