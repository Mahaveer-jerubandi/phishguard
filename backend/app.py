import os
from datetime import timedelta, datetime
from typing import List
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, create_engine, select
from schemas import (
    User, UserCreate, UserRead, ScanCreateURL, ScanCreateEmail, Scan,
    Rule, RuleUpdate, Token
)
from auth import (
    get_password_hash, verify_password, create_access_token,
    get_current_user, get_current_admin
)
from db import get_session, init_db
from models.pipeline import classify_email_from_text, classify_url
from rules.core import get_rules, set_rules

APP_NAME = os.getenv("APP_NAME", "PhishGuard")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")
ALLOW_ORIGINS = os.getenv("ALLOW_ORIGINS", "*").split(",")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

app = FastAPI(title=APP_NAME, version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db(engine)

# -------- Auth --------
@app.post("/auth/register", response_model=UserRead)
def register_user(payload: UserCreate, session: Session = Depends(get_session)):
    existing = session.exec(select(User).where(User.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    total_users = session.exec(select(User)).all()
    role = "admin" if len(total_users) == 0 else payload.role or "user"
    user = User(email=payload.email, password_hash=get_password_hash(payload.password), role=role)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": str(user.id), "role": user.role}, expires_delta=timedelta(hours=8))
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

# -------- Scanning --------
@app.post("/scan/url", response_model=Scan)
def scan_url(payload: ScanCreateURL, current: User = Depends(get_current_user), session: Session = Depends(get_session)):
    verdict = classify_url(payload.url)
    scan = Scan(user_id=current.id, object_type="url", url=payload.url, normalized_text=None,
                verdict=verdict["verdict"], score=verdict["score"], reasons=verdict["reasons"])
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan

@app.post("/scan/email", response_model=Scan)
def scan_email(payload: ScanCreateEmail, current: User = Depends(get_current_user), session: Session = Depends(get_session)):
    verdict = classify_email_from_text(payload.raw_source)
    scan = Scan(user_id=current.id, object_type="email", raw_source=payload.raw_source,
                normalized_text=verdict["normalized_text"], verdict=verdict["verdict"],
                score=verdict["score"], reasons=verdict["reasons"])
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan

# -------- Lists --------
@app.get("/scans", response_model=List[Scan])
def list_my_scans(current: User = Depends(get_current_user), session: Session = Depends(get_session)):
    rows = session.exec(select(Scan).where(Scan.user_id == current.id).order_by(Scan.created_at.desc())).all()
    return rows

@app.get("/admin/scans", response_model=List[Scan])
def list_all_scans(_: User = Depends(get_current_admin), session: Session = Depends(get_session)):
    rows = session.exec(select(Scan).order_by(Scan.created_at.desc())).all()
    return rows

# -------- Rules --------
@app.get("/admin/rules", response_model=List[Rule])
def rules_get(_: User = Depends(get_current_admin)):
    return get_rules()

@app.put("/admin/rules", response_model=List[Rule])
def rules_update(updates: List[RuleUpdate], _: User = Depends(get_current_admin)):
    return set_rules(updates)

# -------- Health --------
@app.get("/healthz")
def healthz():
    return {"ok": True, "time": datetime.utcnow().isoformat()}
