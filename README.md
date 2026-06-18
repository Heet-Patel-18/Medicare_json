# MediCare — Healthcare Appointment System

A full-stack healthcare appointment booking web app built with FastAPI, SQLite, JWT auth, and Jinja2 templates.

## Features
- JWT-based authentication (signup / login / logout)
- Browse 6 pre-seeded specialist doctors
- Book appointments with date, time slot, and reason
- Dashboard with live appointment stats (Total / Confirmed / Pending / Cancelled)
- Cancel appointments
- Edit patient profile

## Project Structure
```
healthcare_app/
├── main.py               # FastAPI backend (routes, models, JWT)
├── requirements.txt
├── healthcare.db         # SQLite DB (auto-created)
├── static/
│   └── uploads/          # Doctor images (optional)
└── Frontend/
    ├── base.html         # Shared CSS + layout
    ├── macros.html       # Reusable sidebar macro
    ├── login.html
    ├── signup.html
    ├── index.html        # Dashboard
    ├── doctors.html      # Doctor listing
    ├── book.html         # Booking form
    └── profile.html      # Patient profile
```

## Setup & Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
uvicorn main:app --reload

# 3. Open in browser
http://localhost:8000
```

## Default Doctors (auto-seeded)
| Doctor | Specialization | Fee |
|--------|---------------|-----|
| Dr. Priya Sharma | Cardiologist | ₹800 |
| Dr. Rohit Mehta | Neurologist | ₹1000 |
| Dr. Anita Desai | Dermatologist | ₹600 |
| Dr. Suresh Patel | Orthopedist | ₹900 |
| Dr. Kavita Rao | Pediatrician | ₹700 |
| Dr. Arjun Nair | General Physician | ₹400 |

## Tech Stack
- **Backend:** FastAPI + SQLAlchemy + SQLite
- **Auth:** JWT (PyJWT) + bcrypt password hashing
- **Templates:** Jinja2
- **Styling:** Pure CSS (Inter font, no frameworks)
