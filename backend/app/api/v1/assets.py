import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import generate_verification_token
from backend.app.models.asset import Asset, AssetAuthorization
from backend.app.models.audit import AuditLog
from backend.app.schemas.asset import (
    AssetCreate,
    AssetResponse,
    AuthorizationRequest,
    AuthorizationResponse,
)
from backend.app.risk.engine import RiskEngine
from backend.app.core.time import utcnow

router = APIRouter(prefix="/assets", tags=["Assets"])

@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    asset_id = f"ast_{uuid.uuid4().hex[:12]}"
    asset = Asset(
        id=asset_id,
        name=payload.name,
        asset_type=payload.asset_type,
        target=payload.target,
        environment=payload.environment,
        owner=payload.owner,
        criticality=payload.criticality,
        created_at=utcnow(),
        updated_at=utcnow()
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    # Calculate initial baseline risk score
    risk_engine = RiskEngine(db)
    risk_engine.calculate_asset_risk(asset.id)

    # Audit log
    audit = AuditLog(
        id=f"adt_{uuid.uuid4().hex[:12]}",
        timestamp=utcnow(),
        actor="admin",
        action="asset_created",
        resource_type="asset",
        resource_id=asset.id,
        details=f"Asset '{asset.name}' ({asset.target}) registered."
    )
    db.add(audit)
    db.commit()

    return asset

@router.get("", response_model=List[AssetResponse])
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.created_at.desc()).all()

@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset

@router.post("/{asset_id}/authorize", response_model=AuthorizationResponse)
def authorize_asset(asset_id: str, payload: AuthorizationRequest, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    auth_id = f"auth_{uuid.uuid4().hex[:12]}"
    challenge = generate_verification_token()
    expires_at = utcnow() + timedelta(days=payload.expires_days)

    # In AegisX, admin_verified grants verified status directly;
    # DNS TXT and HTTP challenge tokens can also be verified
    status_val = "verified" if payload.authorization_method == "admin_verified" else "pending"

    auth_record = AssetAuthorization(
        id=auth_id,
        asset_id=asset_id,
        scope=payload.scope,
        status=status_val,
        challenge_token=challenge,
        authorized_by=payload.authorized_by,
        authorization_method=payload.authorization_method,
        notes=payload.notes,
        verified_at=utcnow() if status_val == "verified" else None,
        expires_at=expires_at,
        created_at=utcnow()
    )
    db.add(auth_record)

    audit = AuditLog(
        id=f"adt_{uuid.uuid4().hex[:12]}",
        timestamp=utcnow(),
        actor=payload.authorized_by,
        action="asset_authorized",
        resource_type="asset",
        resource_id=asset_id,
        details=f"Authorization granted with scope '{payload.scope}' via '{payload.authorization_method}'. Status: {status_val}."
    )
    db.add(audit)
    db.commit()
    db.refresh(auth_record)

    return auth_record

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    return None
