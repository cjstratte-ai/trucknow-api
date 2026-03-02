from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from passlib.context import CryptContext
import os

# ==============================
# CONFIG
# ==============================

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./trucknow.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ==============================
# DATABASE MODELS
# ==============================

class UserDB(Base):
    __tablename__ = "users"
    id              = Column(Integer, primary_key=True, index=True)
    email           = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role            = Column(String, default="customer")   # customer | vendor | admin
    name            = Column(String, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)

class TruckDB(Base):
    __tablename__ = "trucks"
    id              = Column(Integer, primary_key=True, index=True)
    vendor_id       = Column(Integer, index=True)
    provider        = Column(String)
    size            = Column(String)
    payload         = Column(String, nullable=True)
    address         = Column(String, nullable=True)
    lat             = Column(Float, nullable=True)
    lng             = Column(Float, nullable=True)
    hourly          = Column(Float)
    daily           = Column(Float, nullable=True)
    weekend_rate    = Column(Float, nullable=True)
    min_hours       = Column(Integer, default=2)
    mileage_fee     = Column(Float, default=0.85)
    free_miles      = Column(Integer, default=50)
    deposit_amount  = Column(Float, default=0)
    available       = Column(Boolean, default=True)
    plan            = Column(String, default="free")
    insurance_verified = Column(Boolean, default=False)
    created_at      = Column(DateTime, default=datetime.utcnow)

class BookingDB(Base):
    __tablename__ = "bookings"
    id          = Column(Integer, primary_key=True, index=True)
    truck_id    = Column(Integer, index=True)
    customer_id = Column(Integer, index=True)
    date        = Column(String)
    start_time  = Column(String)
    hours       = Column(Integer)
    subtotal    = Column(Float)
    total       = Column(Float)
    deposit     = Column(Float, default=0)
    status      = Column(String, default="pending")  # pending | confirmed | completed | cancelled
    coupon_code = Column(String, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ==============================
# SCHEMAS (Pydantic)
# ==============================

class UserCreate(BaseModel):
    email: str
    password: str
    name: Optional[str] = None
    role: Optional[str] = "customer"

class UserLogin(BaseModel):
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    email: str
    name: Optional[str]
    role: str

class TruckCreate(BaseModel):
    provider: str
    size: str
    payload: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    hourly: float
    daily: Optional[float] = None
    weekend_rate: Optional[float] = None
    min_hours: Optional[int] = 2
    mileage_fee: Optional[float] = 0.85
    free_miles: Optional[int] = 50
    deposit_amount: Optional[float] = 0

class TruckOut(BaseModel):
    id: int
    vendor_id: int
    provider: str
    size: str
    payload: Optional[str]
    address: Optional[str]
    lat: Optional[float]
    lng: Optional[float]
    hourly: float
    daily: Optional[float]
    weekend_rate: Optional[float]
    min_hours: int
    mileage_fee: float
    free_miles: int
    deposit_amount: float
    available: bool
    plan: str
    insurance_verified: bool

    class Config:
        from_attributes = True

class BookingCreate(BaseModel):
    truck_id: int
    date: str
    start_time: str
    hours: int
    subtotal: float
    total: float
    deposit: Optional[float] = 0
    coupon_code: Optional[str] = None

class BookingOut(BaseModel):
    id: int
    truck_id: int
    customer_id: int
    date: str
    start_time: str
    hours: int
    subtotal: float
    total: float
    deposit: float
    status: str
    coupon_code: Optional[str]

    class Config:
        from_attributes = True

# ==============================
# HELPERS
# ==============================

def hash_password(password: str) -> str:
    return pwd_context.hash(password[:72])

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain[:72], hashed)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(UserDB).filter(UserDB.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_role(*roles):
    """Dependency factory — use like: Depends(require_role('admin', 'vendor'))"""
    def checker(current_user: UserDB = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail="Not authorized")
        return current_user
    return checker

# ==============================
# APP
# ==============================

app = FastAPI(title="TruckNow API", version="1.0")

# CORS — in production replace "*" with your Vercel URL
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================
# PUBLIC ROUTES
# ==============================

@app.get("/")
def root():
    return {"message": "TruckNow API is running 🚚"}

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = UserDB(
        email=user.email,
        hashed_password=hash_password(user.password),
        name=user.name,
        role=user.role if user.role in ["customer", "vendor"] else "customer"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Account created", "role": new_user.role}

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.email, "role": db_user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": db_user.role,
        "name": db_user.name,
        "email": db_user.email,
    }

# Public: browse all available trucks (no auth needed)
@app.get("/trucks/public", response_model=List[TruckOut])
def get_public_trucks(db: Session = Depends(get_db)):
    return db.query(TruckDB).filter(TruckDB.available == True, TruckDB.insurance_verified == True).all()

# ==============================
# AUTH ROUTES
# ==============================

@app.get("/me", response_model=UserOut)
def get_me(current_user: UserDB = Depends(get_current_user)):
    return current_user

# ==============================
# VENDOR ROUTES (vendor or admin only)
# ==============================

# Get vendor's own trucks
@app.get("/my-trucks", response_model=List[TruckOut])
def get_my_trucks(
    current_user: UserDB = Depends(require_role("vendor", "admin")),
    db: Session = Depends(get_db)
):
    return db.query(TruckDB).filter(TruckDB.vendor_id == current_user.id).all()

# Add a truck
@app.post("/trucks", response_model=TruckOut)
def create_truck(
    truck: TruckCreate,
    current_user: UserDB = Depends(require_role("vendor", "admin")),
    db: Session = Depends(get_db)
):
    new_truck = TruckDB(**truck.dict(), vendor_id=current_user.id)
    db.add(new_truck)
    db.commit()
    db.refresh(new_truck)
    return new_truck

# Update a truck
@app.put("/trucks/{truck_id}", response_model=TruckOut)
def update_truck(
    truck_id: int,
    truck: TruckCreate,
    current_user: UserDB = Depends(require_role("vendor", "admin")),
    db: Session = Depends(get_db)
):
    db_truck = db.query(TruckDB).filter(TruckDB.id == truck_id, TruckDB.vendor_id == current_user.id).first()
    if not db_truck:
        raise HTTPException(status_code=404, detail="Truck not found")
    for key, val in truck.dict().items():
        setattr(db_truck, key, val)
    db.commit()
    db.refresh(db_truck)
    return db_truck

# Toggle availability
@app.patch("/trucks/{truck_id}/toggle")
def toggle_truck(
    truck_id: int,
    current_user: UserDB = Depends(require_role("vendor", "admin")),
    db: Session = Depends(get_db)
):
    db_truck = db.query(TruckDB).filter(TruckDB.id == truck_id, TruckDB.vendor_id == current_user.id).first()
    if not db_truck:
        raise HTTPException(status_code=404, detail="Truck not found")
    db_truck.available = not db_truck.available
    db.commit()
    return {"available": db_truck.available}

# Delete a truck
@app.delete("/trucks/{truck_id}")
def delete_truck(
    truck_id: int,
    current_user: UserDB = Depends(require_role("vendor", "admin")),
    db: Session = Depends(get_db)
):
    db_truck = db.query(TruckDB).filter(TruckDB.id == truck_id, TruckDB.vendor_id == current_user.id).first()
    if not db_truck:
        raise HTTPException(status_code=404, detail="Truck not found")
    db.delete(db_truck)
    db.commit()
    return {"message": "Truck deleted"}

# Get bookings for vendor's trucks
@app.get("/my-bookings", response_model=List[BookingOut])
def get_vendor_bookings(
    current_user: UserDB = Depends(require_role("vendor", "admin")),
    db: Session = Depends(get_db)
):
    my_truck_ids = [t.id for t in db.query(TruckDB).filter(TruckDB.vendor_id == current_user.id).all()]
    return db.query(BookingDB).filter(BookingDB.truck_id.in_(my_truck_ids)).all()

# ==============================
# CUSTOMER ROUTES
# ==============================

# Create a booking
@app.post("/bookings", response_model=BookingOut)
def create_booking(
    booking: BookingCreate,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    truck = db.query(TruckDB).filter(TruckDB.id == booking.truck_id, TruckDB.available == True).first()
    if not truck:
        raise HTTPException(status_code=404, detail="Truck not available")

    new_booking = BookingDB(**booking.dict(), customer_id=current_user.id, status="confirmed")
    db.add(new_booking)
    db.commit()
    db.refresh(new_booking)
    return new_booking

# Get customer's own bookings
@app.get("/my-booking-history", response_model=List[BookingOut])
def get_my_bookings(
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(BookingDB).filter(BookingDB.customer_id == current_user.id).all()

# ==============================
# ADMIN ROUTES
# ==============================

@app.get("/admin/users", response_model=List[UserOut])
def admin_get_users(
    current_user: UserDB = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    return db.query(UserDB).all()

@app.get("/admin/trucks", response_model=List[TruckOut])
def admin_get_trucks(
    current_user: UserDB = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    return db.query(TruckDB).all()

@app.get("/admin/bookings", response_model=List[BookingOut])
def admin_get_bookings(
    current_user: UserDB = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    return db.query(BookingDB).all()

# Approve truck insurance
@app.patch("/admin/trucks/{truck_id}/verify-insurance")
def verify_insurance(
    truck_id: int,
    current_user: UserDB = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    truck = db.query(TruckDB).filter(TruckDB.id == truck_id).first()
    if not truck:
        raise HTTPException(status_code=404, detail="Truck not found")
    truck.insurance_verified = True
    db.commit()
    return {"message": "Insurance verified"}
 
