from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt

from sqlalchemy import Column, Integer, String, Float, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from passlib.context import CryptContext

# ==============================
# CONFIG
# ==============================

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = "sqlite:///./trucknow.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
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

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    role = Column(String)

class TruckDB(Base):
    __tablename__ = "trucks"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String)
    size = Column(String)
    hourly = Column(Float)

Base.metadata.create_all(bind=engine)

# ==============================
# SCHEMAS
# ==============================

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Truck(BaseModel):
    id: Optional[int] = None
    provider: str
    size: str
    hourly: float

# ==============================
# SECURITY FUNCTIONS
# ==============================

def hash_password(password: str):
    return pwd_context.hash(password[:72])

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password[:72], hashed_password)

def create_access_token(data: dict):
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
        role: str = payload.get("role")

        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(UserDB).filter(UserDB.email == email).first()

    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return {"email": user.email, "role": user.role}

# ==============================
# FASTAPI APP
# ==============================

app = FastAPI()

@app.get("/")
def root():
    return {"message": "TruckNow API is running 🚚"}
@app.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from jose import JWTError, jwt

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        role: str = payload.get("role")

        if email is None:
            raise credentials_exception

        return {"email": email, "role": role}

    except JWTError:
        raise credentials_exception

# ==============================
# AUTH ROUTES
# ==============================

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(UserDB).filter(UserDB.email == user.email).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = UserDB(
        email=user.email,
        hashed_password=hash_password(user.password),
        role="admin"
    )

    db.add(new_user)
    db.commit()

    return {"message": "User created successfully"}

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.email == user.email).first()

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({
        "sub": db_user.email,
        "role": db_user.role
    })

    return {"access_token": access_token, "token_type": "bearer"}

# ==============================
# PROTECTED TRUCK ROUTES
# ==============================

@app.get("/trucks", response_model=List[Truck])
def get_trucks(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(TruckDB).all()

@app.post("/trucks", response_model=Truck)
def create_truck(truck: Truck, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    new_truck = TruckDB(
        provider=truck.provider,
        size=truck.size,
        hourly=truck.hourly
    )

    db.add(new_truck)
    db.commit()
    db.refresh(new_truck)

    return new_truck