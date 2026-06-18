from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine, String, select, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
from typing import Optional, List

# ==========================================
# 1. SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "healthcare_secret_key_dev_2025"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))


def get_password_hash(password):
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==========================================
# 2. DATABASE SETUP
# ==========================================
engine = create_engine("sqlite:///healthcare.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(100), unique=True)
    phone: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20), default="patient")  # patient | doctor


class Doctor(Base):
    __tablename__ = "doctors"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # linked User account
    name: Mapped[str] = mapped_column(String(100))
    specialization: Mapped[str] = mapped_column(String(100))
    experience: Mapped[str] = mapped_column(String(50))
    available_days: Mapped[str] = mapped_column(String(200))
    fee: Mapped[str] = mapped_column(String(30))
    image_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class Appointment(Base):
    __tablename__ = "appointments"
    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(Integer)
    doctor_id: Mapped[int] = mapped_column(Integer)
    patient_name: Mapped[str] = mapped_column(String(100))
    doctor_name: Mapped[str] = mapped_column(String(100))
    specialization: Mapped[str] = mapped_column(String(100))
    date: Mapped[str] = mapped_column(String(30))
    time: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="Pending")  # Pending | Confirmed | Rejected | Cancelled
    doctor_note: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)


Base.metadata.create_all(bind=engine)

# ==========================================
# 3. PYDANTIC SCHEMAS (request/response bodies)
# ==========================================

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    email: str
    phone: Optional[str] = None
    role: str


class DoctorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    specialization: str
    experience: str
    available_days: str
    fee: str
    image_path: Optional[str] = None


class AppointmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    patient_id: int
    doctor_id: int
    patient_name: str
    doctor_name: str
    specialization: str
    date: str
    time: str
    reason: str
    status: str
    doctor_note: Optional[str] = None


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class SignupIn(BaseModel):
    name: str
    email: str
    phone: Optional[str] = ""
    password: str


class LoginIn(BaseModel):
    email: str
    password: str


class ProfileUpdateIn(BaseModel):
    name: str
    phone: Optional[str] = ""


class BookingIn(BaseModel):
    date: str
    time: str
    reason: str


class DoctorNoteIn(BaseModel):
    doctor_note: Optional[str] = ""


class DashboardStats(BaseModel):
    appointments: List[AppointmentOut]
    total: int
    confirmed: int
    pending: int
    cancelled: int


class DoctorDashboardStats(BaseModel):
    doctor: DoctorOut
    appointments: List[AppointmentOut]
    total: int
    pending: int
    confirmed: int
    rejected: int


# ==========================================
# 4. FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI(title="MediCare API")
app.mount("/static", StaticFiles(directory="static"), name="static")

bearer_scheme = HTTPBearer(auto_error=False)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Keep validation errors as clean JSON instead of FastAPI's default verbose shape
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user = db.scalars(select(User).where(User.email == email)).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_current_doctor(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Doctor:
    if current_user.role != "doctor":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Doctor access required")
    doctor = db.scalars(select(Doctor).where(Doctor.user_id == current_user.id)).first()
    if doctor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Doctor profile not found")
    return doctor


def seed_data(db: Session):
    if db.scalars(select(Doctor)).first():
        return

    doctor_data = [
        ("Dr. Priya Sharma", "priya@medicare.com", "Cardiologist", "12 years", "Mon, Wed, Fri", "₹800"),
        ("Dr. Rohit Mehta", "rohit@medicare.com", "Neurologist", "8 years", "Tue, Thu, Sat", "₹1000"),
        ("Dr. Anita Desai", "anita@medicare.com", "Dermatologist", "10 years", "Mon, Tue, Thu", "₹600"),
        ("Dr. Suresh Patel", "suresh@medicare.com", "Orthopedist", "15 years", "Wed, Fri, Sat", "₹900"),
        ("Dr. Kavita Rao", "kavita@medicare.com", "Pediatrician", "6 years", "Mon, Wed, Fri", "₹700"),
        ("Dr. Arjun Nair", "arjun@medicare.com", "General Physician", "5 years", "Mon, Tue, Wed, Thu, Fri", "₹400"),
    ]
    default_pw = get_password_hash("doctor123")

    for name, email, spec, exp, days, fee in doctor_data:
        user = User(name=name, email=email, hashed_password=default_pw, role="doctor")
        db.add(user)
        db.flush()
        doctor = Doctor(user_id=user.id, name=name, specialization=spec,
                         experience=exp, available_days=days, fee=fee)
        db.add(doctor)

    db.commit()


with SessionLocal() as _db:
    seed_data(_db)

# ==========================================
# 5. AUTH ROUTES
# ==========================================

@app.post("/signup", response_model=TokenOut)
def signup(payload: SignupIn, db: Session = Depends(get_db)):
    if db.scalars(select(User).where(User.email == payload.email)).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered.")
    new_user = User(name=payload.name, email=payload.email, phone=payload.phone,
                     hashed_password=get_password_hash(payload.password))
    db.add(new_user)
    db.commit()
    token = create_access_token(data={"sub": new_user.email})
    return TokenOut(access_token=token, user=UserOut.model_validate(new_user))


@app.post("/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.scalars(select(User).where(User.email == payload.email)).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    token = create_access_token(data={"sub": user.email})
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@app.post("/logout")
def logout():
    # JWTs are stateless, so there's nothing to invalidate server-side.
    # The client should just discard the token.
    return {"message": "Logged out. Discard the access token client-side."}

# ==========================================
# 6. PATIENT ROUTES
# ==========================================

@app.get("/", response_model=DashboardStats)
def dashboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == "doctor":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail="Doctor accounts should use /doctor/dashboard")
    appointments = db.scalars(select(Appointment).where(Appointment.patient_id == current_user.id)).all()
    total = len(appointments)
    confirmed = sum(1 for a in appointments if a.status == "Confirmed")
    pending = sum(1 for a in appointments if a.status == "Pending")
    cancelled = sum(1 for a in appointments if a.status in ("Cancelled", "Rejected"))
    return DashboardStats(
        appointments=[AppointmentOut.model_validate(a) for a in appointments],
        total=total, confirmed=confirmed, pending=pending, cancelled=cancelled,
    )


@app.get("/doctors", response_model=List[DoctorOut])
def doctors_list(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doctors = db.scalars(select(Doctor)).all()
    return [DoctorOut.model_validate(d) for d in doctors]


@app.get("/book/{doctor_id}", response_model=DoctorOut)
def book_page(doctor_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doctor = db.get(Doctor, doctor_id)
    if not doctor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Doctor not found")
    return DoctorOut.model_validate(doctor)


@app.post("/book/{doctor_id}", response_model=AppointmentOut, status_code=status.HTTP_201_CREATED)
def book_appointment(doctor_id: int, payload: BookingIn, db: Session = Depends(get_db),
                      current_user: User = Depends(get_current_user)):
    doctor = db.get(Doctor, doctor_id)
    if not doctor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Doctor not found")
    appt = Appointment(
        patient_id=current_user.id, doctor_id=doctor_id,
        patient_name=current_user.name, doctor_name=doctor.name,
        specialization=doctor.specialization, date=payload.date, time=payload.time,
        reason=payload.reason, status="Pending",
    )
    db.add(appt)
    db.commit()
    db.refresh(appt)
    return AppointmentOut.model_validate(appt)


@app.post("/cancel/{appointment_id}", response_model=AppointmentOut)
def cancel_appointment(appointment_id: int, current_user: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    appt = db.get(Appointment, appointment_id)
    if not appt or appt.patient_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found")
    if appt.status != "Pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail="Only pending appointments can be cancelled")
    appt.status = "Cancelled"
    db.commit()
    db.refresh(appt)
    return AppointmentOut.model_validate(appt)


@app.get("/profile", response_model=UserOut)
def profile_get(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)


@app.put("/profile", response_model=UserOut)
def profile_update(payload: ProfileUpdateIn, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    current_user.name = payload.name
    current_user.phone = payload.phone
    db.commit()
    db.refresh(current_user)
    return UserOut.model_validate(current_user)

# ==========================================
# 7. DOCTOR ROUTES
# ==========================================

@app.get("/doctor/dashboard", response_model=DoctorDashboardStats)
def doctor_dashboard(doctor: Doctor = Depends(get_current_doctor), db: Session = Depends(get_db)):
    appointments = db.scalars(select(Appointment).where(Appointment.doctor_id == doctor.id)).all()
    total = len(appointments)
    pending = sum(1 for a in appointments if a.status == "Pending")
    confirmed = sum(1 for a in appointments if a.status == "Confirmed")
    rejected = sum(1 for a in appointments if a.status == "Rejected")
    return DoctorDashboardStats(
        doctor=DoctorOut.model_validate(doctor),
        appointments=[AppointmentOut.model_validate(a) for a in appointments],
        total=total, pending=pending, confirmed=confirmed, rejected=rejected,
    )


@app.get("/doctor/appointment/{appt_id}", response_model=AppointmentOut)
def doctor_appt_detail(appt_id: int, doctor: Doctor = Depends(get_current_doctor), db: Session = Depends(get_db)):
    appt = db.get(Appointment, appt_id)
    if not appt or appt.doctor_id != doctor.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found")
    return AppointmentOut.model_validate(appt)


@app.post("/doctor/approve/{appt_id}", response_model=AppointmentOut)
def approve_appointment(appt_id: int, payload: DoctorNoteIn, db: Session = Depends(get_db),
                         doctor: Doctor = Depends(get_current_doctor)):
    appt = db.get(Appointment, appt_id)
    if not appt or appt.doctor_id != doctor.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found")
    if appt.status != "Pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only pending appointments can be approved")
    appt.status = "Confirmed"
    appt.doctor_note = payload.doctor_note or "Your appointment has been confirmed."
    db.commit()
    db.refresh(appt)
    return AppointmentOut.model_validate(appt)


@app.post("/doctor/reject/{appt_id}", response_model=AppointmentOut)
def reject_appointment(appt_id: int, payload: DoctorNoteIn, db: Session = Depends(get_db),
                        doctor: Doctor = Depends(get_current_doctor)):
    appt = db.get(Appointment, appt_id)
    if not appt or appt.doctor_id != doctor.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found")
    if appt.status != "Pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only pending appointments can be rejected")
    appt.status = "Rejected"
    appt.doctor_note = payload.doctor_note or "Appointment could not be accommodated."
    db.commit()
    db.refresh(appt)
    return AppointmentOut.model_validate(appt)