"""
Example FastAPI backend for the TruckNow project.

This module defines a simple API with endpoints for listing trucks and creating
bookings. The data is stored in in-memory lists for demonstration purposes.

You should eventually replace the hard-coded data structures with a real
 database (e.g. PostgreSQL, SQLite) using an ORM like SQLAlchemy or
Tortoise-ORM. This code is intended to help you get started quickly and
understand the basic concepts.
"""

from __future__ import annotations
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# FastAPI application and CORS configuration
app = FastAPI(title="TruckNow API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models
class Pricing(BaseModel):
    hourly: float
    daily: float
    weekendRate: float
    minimumHours: int
    afterHoursSurcharge: float
    mileageFee: float
    freeMiles: int

class Insurance(BaseModel):
    provider: str
    policyNo: str
    expiry: str
    verified: bool

class AddOn(BaseModel):
    id: str
    label: str
    price: float
    included: Optional[bool] = False

class Coupon(BaseModel):
    code: str
    discount: float
    type: str
    uses: int
    maxUses: int
    active: bool

class Deposit(BaseModel):
    required: bool
    amount: float

class Truck(BaseModel):
    id: int
    vendorId: int
    provider: str
    size: str
    payload: str
    color: str
    img: str
    available: bool
    payoutMethod: Optional[str]
    status: str
    plan: str
    boostActive: bool
    boostExpiry: Optional[str]
    lat: float
    lng: float
    address: str
    earnings: float
    bookingsCount: int
    rating: float
    reviews: int
    pricing: Pricing
    insurance: Insurance
    deposit: Deposit
    addons: List[AddOn]
    coupons: List[Coupon]
    schedule: dict[str, str]
    blockedDates: List[str]
    features: List[str]

class Booking(BaseModel):
    id: str
    customer: str
    truckId: int
    date: str
    hours: int
    startTime: str
    addons: List[str]
    coupon: Optional[str]
    subtotal: float
    deposit: float
    insuranceFee: float
    platformFee: float
    total: float
    status: str

# In-memory data stores
trucks_db: List[Truck] = [
    Truck(
        id=1,
        vendorId=10,
        provider="HaulPro",
        size="10 ft",
        payload="2,000 lbs",
        color="#FF6B35",
        img="🚛",
        available=True,
        payoutMethod="stripe",
        status="approved",
        plan="pro",
        boostActive=True,
        boostExpiry="2026-02-24",
        lat=30.2672,
        lng=-97.7431,
        address="East Austin, TX",
        earnings=4290,
        bookingsCount=31,
        rating=4.8,
        reviews=312,
        pricing=Pricing(
            hourly=39,
            daily=249,
            weekendRate=49,
            minimumHours=2,
            afterHoursSurcharge=15,
            mileageFee=0.85,
            freeMiles=50,
        ),
        insurance=Insurance(
            provider="State Farm",
            policyNo="SF-2024-8821",
            expiry="2027-03-01",
            verified=True,
        ),
        deposit=Deposit(required=True, amount=150),
        addons=[
            AddOn(id="ramp", label="Loading Ramp", price=0, included=True),
            AddOn(id="dolly", label="Moving Dolly", price=15),
            AddOn(id="pads", label="Furniture Pads (12)", price=20),
            AddOn(id="straps", label="Cargo Straps", price=10),
        ],
        coupons=[
            Coupon(code="HAUL10", discount=10, type="percent", uses=0, maxUses=50, active=True),
            Coupon(code="FIRST20", discount=20, type="flat", uses=3, maxUses=100, active=True),
        ],
        schedule={
            "mon": "7am–8pm",
            "tue": "7am–8pm",
            "wed": "7am–8pm",
            "thu": "7am–8pm",
            "fri": "7am–9pm",
            "sat": "8am–6pm",
            "sun": "Closed",
        },
        blockedDates=["2026-02-20", "2026-02-21"],
        features=["Ramp included", "Unlimited miles", "24/7 roadside"],
    ),
    Truck(
        id=2,
        vendorId=10,
        provider="HaulPro XL",
        size="16 ft",
        payload="4,000 lbs",
        color="#E63946",
        img="🚚",
        available=True,
        payoutMethod="stripe",
        status="approved",
        plan="pro",
        boostActive=False,
        boostExpiry=None,
        lat=30.2780,
        lng=-97.7200,
        address="East Austin, TX",
        earnings=2100,
        bookingsCount=14,
        rating=4.7,
        reviews=89,
        pricing=Pricing(
            hourly=65,
            daily=399,
            weekendRate=75,
            minimumHours=3,
            afterHoursSurcharge=20,
            mileageFee=1.00,
            freeMiles=75,
        ),
        insurance=Insurance(
            provider="State Farm",
            policyNo="SF-2024-8822",
            expiry="2027-03-01",
            verified=True,
        ),
        deposit=Deposit(required=True, amount=250),
        addons=[
            AddOn(id="liftgate", label="Liftgate", price=35),
            AddOn(id="dolly", label="Moving Dolly", price=15),
            AddOn(id="pads", label="Furniture Pads (24)", price=35),
            AddOn(id="gps", label="GPS Tracker", price=0, included=True),
        ],
        coupons=[
            Coupon(code="XL15", discount=15, type="percent", uses=1, maxUses=30, active=True),
        ],
        schedule={
            "mon": "8am–7pm",
            "tue": "8am–7pm",
            "wed": "8am–7pm",
            "thu": "8am–7pm",
            "fri": "8am–8pm",
            "sat": "9am–5pm",
            "sun": "Closed",
        },
        blockedDates=["2026-02-25"],
        features=["Liftgate", "GPS tracker", "24/7 roadside"],
    ),
]

# Booking storage
bookings_db: List[Booking] = []

# API Endpoints
@app.get("/trucks", response_model=List[Truck])
async def list_trucks() -> List[Truck]:
    """Return a list of all available trucks."""
    return trucks_db

@app.get("/trucks/{truck_id}", response_model=Truck)
async def get_truck(truck_id: int) -> Truck:
    """Return a single truck by ID. Raises 404 if not found."""
    for truck in trucks_db:
        if truck.id == truck_id:
            return truck
    raise HTTPException(status_code=404, detail="Truck not found")

@app.post("/bookings", response_model=Booking)
async def create_booking(booking: Booking) -> Booking:
    """Create a new booking after validating the truck ID."""
    if not any(truck.id == booking.truckId for truck in trucks_db):
        raise HTTPException(status_code=400, detail="Invalid truckId")
    bookings_db.append(booking)
    return booking

@app.get("/bookings", response_model=List[Booking])
async def list_bookings() -> List[Booking]:
    """Return all existing bookings."""
    return bookings_db

