# main.py
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Header, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

app = FastAPI(title="ALGORITHMIC", version="4.0.0")

DB_FILE = "algorithmic_enterprise.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

SESSION_LIFETIME_DAYS = 7
PBKDF2_ITERATIONS = 200_000
ALLOWED_UPLOAD_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

VALID_MODULES = ['students', 'teachers', 'classrooms', 'syllabus', 'attendance', 'invigilation', 'fees']


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS institutes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institute_name TEXT NOT NULL,
            full_name TEXT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            institute_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(institute_id) REFERENCES institutes(id)
        )
    """)
    # branches now belong to a single institute -> real multi-tenancy
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS branches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institute_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            UNIQUE(institute_id, name),
            FOREIGN KEY(institute_id) REFERENCES institutes(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER,
            name TEXT,
            email TEXT,
            course TEXT,
            status TEXT,
            document TEXT,
            FOREIGN KEY(branch_id) REFERENCES branches(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER,
            name TEXT,
            subject TEXT,
            department TEXT,
            document TEXT,
            FOREIGN KEY(branch_id) REFERENCES branches(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS classrooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER,
            room_no TEXT,
            capacity INTEGER,
            building TEXT,
            document TEXT,
            FOREIGN KEY(branch_id) REFERENCES branches(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS syllabus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER,
            subject TEXT,
            semester TEXT,
            units INTEGER,
            document TEXT,
            FOREIGN KEY(branch_id) REFERENCES branches(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER,
            student_name TEXT,
            date TEXT,
            status TEXT,
            document TEXT,
            FOREIGN KEY(branch_id) REFERENCES branches(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS timetables_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER,
            batch_name TEXT,
            day TEXT,
            time_slot TEXT,
            subject TEXT,
            teacher TEXT,
            room TEXT,
            FOREIGN KEY(branch_id) REFERENCES branches(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS invigilation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER,
            teacher_name TEXT,
            exam_date TEXT,
            room TEXT,
            document TEXT,
            FOREIGN KEY(branch_id) REFERENCES branches(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER,
            student_name TEXT,
            amount_inr REAL,
            status TEXT,
            due_date TEXT,
            document TEXT,
            FOREIGN KEY(branch_id) REFERENCES branches(id)
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()


def create_session(institute_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(days=SESSION_LIFETIME_DAYS)).isoformat()
    conn = get_conn()
    conn.execute(
        "INSERT INTO sessions (token, institute_id, expires_at) VALUES (?, ?, ?)",
        (token, institute_id, expires_at),
    )
    conn.commit()
    conn.close()
    return token


class CurrentInstitute(BaseModel):
    id: int
    institute_name: str
    full_name: str
    email: str


def get_current_institute(authorization: str = Header(None)) -> CurrentInstitute:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE token = ?", (token,))
    session = cursor.fetchone()
    if not session:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    if datetime.fromisoformat(session["expires_at"]) < datetime.utcnow():
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Session expired, please log in again")

    cursor.execute("SELECT * FROM institutes WHERE id = ?", (session["institute_id"],))
    institute = cursor.fetchone()
    conn.close()
    if not institute:
        raise HTTPException(status_code=401, detail="Invalid session")

    return CurrentInstitute(
        id=institute["id"],
        institute_name=institute["institute_name"],
        full_name=institute["full_name"] or "",
        email=institute["email"],
    )


def verify_branch_ownership(branch_id: int, institute_id: int):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM branches WHERE id = ? AND institute_id = ?", (branch_id, institute_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Branch not found")


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    institute_name: str
    full_name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/api/auth/signup")
def signup(req: SignupRequest):
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    salt = secrets.token_hex(16)
    password_hash = hash_password(req.password, salt)

    conn = get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO institutes (institute_name, full_name, email, password_hash, password_salt, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (req.institute_name, req.full_name, req.email.lower(), password_hash, salt, datetime.utcnow().isoformat()),
        )
        institute_id = cursor.lastrowid
        # every new institute gets one starter branch
        cursor.execute(
            "INSERT INTO branches (institute_id, name) VALUES (?, ?)",
            (institute_id, "Main Campus"),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="An account with this email already exists")
    conn.close()

    token = create_session(institute_id)
    return {"token": token, "institute_name": req.institute_name, "full_name": req.full_name}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM institutes WHERE email = ?", (req.email.lower(),))
    institute = cursor.fetchone()
    conn.close()

    # Deliberately same error for "no such email" and "wrong password" so
    # attackers can't use this endpoint to find out which emails are registered.
    invalid = HTTPException(status_code=401, detail="Invalid email or password")
    if not institute:
        raise invalid

    computed_hash = hash_password(req.password, institute["password_salt"])
    if not secrets.compare_digest(computed_hash, institute["password_hash"]):
        raise invalid

    token = create_session(institute["id"])
    return {
        "token": token,
        "institute_name": institute["institute_name"],
        "full_name": institute["full_name"] or "",
    }


@app.post("/api/auth/logout")
def logout(authorization: str = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        conn = get_conn()
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    return {"status": "logged out"}


# ---------------------------------------------------------------------------
# Branches
# ---------------------------------------------------------------------------

class BranchCreate(BaseModel):
    name: str


@app.get("/api/branches")
def get_branches(institute: CurrentInstitute = Depends(get_current_institute)):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM branches WHERE institute_id = ?", (institute.id,))
    branches = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return branches


@app.post("/api/branches")
def add_branch(branch: BranchCreate, institute: CurrentInstitute = Depends(get_current_institute)):
    conn = get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO branches (institute_id, name) VALUES (?, ?)",
            (institute.id, branch.name),
        )
        conn.commit()
        branch_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Branch already exists")
    conn.close()
    return {"id": branch_id, "name": branch.name}


# ---------------------------------------------------------------------------
# Generic records (students / teachers / classrooms / syllabus / attendance / invigilation / fees)
# ---------------------------------------------------------------------------

@app.get("/api/records/{module}/{branch_id}")
def get_records(module: str, branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    verify_branch_ownership(branch_id, institute.id)

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # module is validated against VALID_MODULES above, so this is safe from injection
    cursor.execute(f"SELECT * FROM {module} WHERE branch_id = ?", (branch_id,))
    records = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return records


def save_upload(file: UploadFile) -> str:
    """Validates type/size and stores the file under a random name (never the
    original filename) so a crafted filename can't be used to write outside
    the uploads directory."""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}",
        )
    contents = file.file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File too large (max 5 MB)")

    filename = f"{secrets.token_hex(12)}{ext}"
    with open(os.path.join(UPLOAD_DIR, filename), "wb") as buffer:
        buffer.write(contents)
    return filename


@app.post("/api/records/{module}")
async def add_record(
    module: str,
    branch_id: int = Form(...),
    data_json: str = Form(...),
    file: UploadFile = File(None),
    institute: CurrentInstitute = Depends(get_current_institute),
):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    verify_branch_ownership(branch_id, institute.id)

    data = json.loads(data_json)
    doc_filename = save_upload(file) if file else None

    conn = get_conn()
    cursor = conn.cursor()

    if module == 'students':
        cursor.execute("INSERT INTO students (branch_id, name, email, course, status, document) VALUES (?, ?, ?, ?, ?, ?)",
                       (branch_id, data.get('name'), data.get('email'), data.get('course'), data.get('status', 'Active'), doc_filename))
    elif module == 'teachers':
        cursor.execute("INSERT INTO teachers (branch_id, name, subject, department, document) VALUES (?, ?, ?, ?, ?)",
                       (branch_id, data.get('name'), data.get('subject'), data.get('department'), doc_filename))
    elif module == 'classrooms':
        cursor.execute("INSERT INTO classrooms (branch_id, room_no, capacity, building, document) VALUES (?, ?, ?, ?, ?)",
                       (branch_id, data.get('room_no'), data.get('capacity'), data.get('building'), doc_filename))
    elif module == 'syllabus':
        cursor.execute("INSERT INTO syllabus (branch_id, subject, semester, units, document) VALUES (?, ?, ?, ?, ?)",
                       (branch_id, data.get('subject'), data.get('semester'), data.get('units'), doc_filename))
    elif module == 'attendance':
        cursor.execute("INSERT INTO attendance (branch_id, student_name, date, status, document) VALUES (?, ?, ?, ?, ?)",
                       (branch_id, data.get('student_name'), data.get('date'), data.get('status'), doc_filename))
    elif module == 'invigilation':
        cursor.execute("INSERT INTO invigilation (branch_id, teacher_name, exam_date, room, document) VALUES (?, ?, ?, ?, ?)",
                       (branch_id, data.get('teacher_name'), data.get('exam_date'), data.get('room'), doc_filename))
    elif module == 'fees':
        cursor.execute("INSERT INTO fees (branch_id, student_name, amount_inr, status, due_date, document) VALUES (?, ?, ?, ?, ?, ?)",
                       (branch_id, data.get('student_name'), data.get('amount_inr'), data.get('status'), data.get('due_date'), doc_filename))

    conn.commit()
    record_id = cursor.lastrowid
    conn.close()
    return {"id": record_id, "status": "success"}


# ---------------------------------------------------------------------------
# Timetable generation
# ---------------------------------------------------------------------------

@app.get("/api/timetable/slots/{branch_id}")
def get_timetable_slots(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    verify_branch_ownership(branch_id, institute.id)
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM timetables_slots WHERE branch_id = ?", (branch_id,))
    slots = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return slots


class TimetableGenerateRequest(BaseModel):
    branch_id: int
    batch_name: str
    teachers_config: list  # [{name, subject, lectures_per_week, unavailable_days: []}]
    timings: list  # ["09:00 AM - 10:00 AM", ...]


def run_timetable_generation(conn, branch_id: int, batch_name: str, teachers_config: list, timings: list):
    """Core conflict-checked scheduling logic, shared by the API endpoint and
    the demo seeder so the demo shows off the exact same real algorithm."""
    cursor = conn.cursor()

    # Clear old slots for this batch only - other batches' slots stay intact
    # so we can still check teacher/room conflicts against them below.
    cursor.execute("DELETE FROM timetables_slots WHERE branch_id = ? AND batch_name = ?", (branch_id, batch_name))

    # Real classrooms for this branch, used for room assignment instead of a hardcoded room.
    cursor.execute("SELECT room_no FROM classrooms WHERE branch_id = ? ORDER BY id", (branch_id,))
    available_rooms = [row[0] for row in cursor.fetchall() if row[0]]

    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    generated_slots = []
    warnings = []

    for t_config in teachers_config:
        teacher_name = t_config['name']
        subject = t_config['subject']
        target_lectures = int(t_config['lectures_per_week'])
        unavailable = t_config.get('unavailable_days', [])

        assigned_count = 0
        for day in days:
            if day in unavailable:
                continue
            if assigned_count >= target_lectures:
                break
            for slot_time in timings:
                if assigned_count >= target_lectures:
                    break

                # 1. Is this batch already busy at this day/time?
                cursor.execute("""
                    SELECT COUNT(*) FROM timetables_slots
                    WHERE branch_id = ? AND batch_name = ? AND day = ? AND time_slot = ?
                """, (branch_id, batch_name, day, slot_time))
                if cursor.fetchone()[0] > 0:
                    continue

                # 2. Is this teacher already teaching a DIFFERENT batch at this day/time?
                #    (this is the check the old version never did)
                cursor.execute("""
                    SELECT COUNT(*) FROM timetables_slots
                    WHERE branch_id = ? AND day = ? AND time_slot = ? AND teacher = ?
                """, (branch_id, day, slot_time, teacher_name))
                if cursor.fetchone()[0] > 0:
                    continue

                # 3. Find a real, currently-free classroom for this day/time
                room = None
                for candidate_room in available_rooms:
                    cursor.execute("""
                        SELECT COUNT(*) FROM timetables_slots
                        WHERE branch_id = ? AND day = ? AND time_slot = ? AND room = ?
                    """, (branch_id, day, slot_time, candidate_room))
                    if cursor.fetchone()[0] == 0:
                        room = candidate_room
                        break
                if room is None:
                    room = "Unassigned (no free classroom)" if available_rooms else "Unassigned (add a classroom)"

                cursor.execute("""
                    INSERT INTO timetables_slots (branch_id, batch_name, day, time_slot, subject, teacher, room)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (branch_id, batch_name, day, slot_time, subject, teacher_name, room))
                generated_slots.append({"day": day, "time_slot": slot_time, "subject": subject, "teacher": teacher_name, "room": room})
                assigned_count += 1

        if assigned_count < target_lectures:
            warnings.append(
                f"{teacher_name}: only scheduled {assigned_count}/{target_lectures} lectures "
                f"(not enough free day/time slots without a conflict)."
            )

    return {"status": "success", "slots": generated_slots, "warnings": warnings}


@app.post("/api/timetable/generate")
def generate_timetable(req: TimetableGenerateRequest, institute: CurrentInstitute = Depends(get_current_institute)):
    verify_branch_ownership(req.branch_id, institute.id)
    conn = get_conn()
    result = run_timetable_generation(conn, req.branch_id, req.batch_name, req.teachers_config, req.timings)
    conn.commit()
    conn.close()
    return result


# ---------------------------------------------------------------------------
# Demo account seeding (for sales pitches / walkthroughs)
# ---------------------------------------------------------------------------
#
# Hitting this endpoint wipes and rebuilds ONE fixed demo institute so you
# always have a realistic, fully-populated account ready to show a prospect,
# without touching any real customer's data. Safe to call as many times as
# you want (e.g. right before every pitch) - it always resets to a clean slate.
#
# Protect it with a secret so randoms on the internet can't spam your DB:
# set an environment variable DEMO_SEED_KEY on Render to your own secret,
# then call this with header  X-Demo-Seed-Key: <that secret>
# If you don't set the env var, it falls back to "change-me-demo-key" -
# change that in Render before going live with real customers.

DEMO_SEED_KEY = os.environ.get("DEMO_SEED_KEY", "change-me-demo-key")
DEMO_EMAIL = "demo@algorithmic.app"
DEMO_PASSWORD = "DemoAccess2026!"
DEMO_INSTITUTE_NAME = "Horizon Public School"


def require_demo_key(x_demo_seed_key: str = Header(None)):
    if not x_demo_seed_key or not secrets.compare_digest(x_demo_seed_key, DEMO_SEED_KEY):
        raise HTTPException(status_code=403, detail="Invalid or missing demo seed key")


@app.post("/api/demo/seed")
def seed_demo_account(_: None = Depends(require_demo_key)):
    conn = get_conn()
    cursor = conn.cursor()

    # Wipe any previous demo institute + everything under its branches.
    cursor.execute("SELECT id FROM institutes WHERE email = ?", (DEMO_EMAIL,))
    existing = cursor.fetchone()
    if existing:
        old_institute_id = existing[0]
        cursor.execute("SELECT id FROM branches WHERE institute_id = ?", (old_institute_id,))
        old_branch_ids = [r[0] for r in cursor.fetchall()]
        for bid in old_branch_ids:
            for table in ['students', 'teachers', 'classrooms', 'syllabus', 'attendance',
                          'timetables_slots', 'invigilation', 'fees']:
                cursor.execute(f"DELETE FROM {table} WHERE branch_id = ?", (bid,))
        cursor.execute("DELETE FROM branches WHERE institute_id = ?", (old_institute_id,))
        cursor.execute("DELETE FROM sessions WHERE institute_id = ?", (old_institute_id,))
        cursor.execute("DELETE FROM institutes WHERE id = ?", (old_institute_id,))
        conn.commit()

    # Fresh demo institute + branch.
    salt = secrets.token_hex(16)
    password_hash = hash_password(DEMO_PASSWORD, salt)
    cursor.execute(
        """INSERT INTO institutes (institute_name, full_name, email, password_hash, password_salt, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (DEMO_INSTITUTE_NAME, "Demo Admin", DEMO_EMAIL, password_hash, salt, datetime.utcnow().isoformat()),
    )
    institute_id = cursor.lastrowid
    cursor.execute("INSERT INTO branches (institute_id, name) VALUES (?, ?)", (institute_id, "Main Campus"))
    branch_id = cursor.lastrowid
    conn.commit()

    # --- Teachers ---
    teachers = [
        ("Dr. Ramesh Kumar", "Mathematics", "Science Department"),
        ("Mrs. Anjali Verma", "Physics", "Science Department"),
        ("Mr. Suresh Iyer", "Chemistry", "Science Department"),
        ("Ms. Priya Nair", "English", "Languages Department"),
        ("Mr. Vikram Joshi", "Computer Science", "Technology Department"),
        ("Mrs. Kavita Desai", "History", "Humanities Department"),
    ]
    for name, subject, department in teachers:
        cursor.execute(
            "INSERT INTO teachers (branch_id, name, subject, department, document) VALUES (?, ?, ?, ?, NULL)",
            (branch_id, name, subject, department),
        )
    conn.commit()

    # --- Classrooms ---
    classrooms = [
        ("Room 101", 45, "Main Building"),
        ("Room 102", 45, "Main Building"),
        ("Room 201", 60, "Science Block"),
        ("Computer Lab", 30, "Technology Block"),
    ]
    for room_no, capacity, building in classrooms:
        cursor.execute(
            "INSERT INTO classrooms (branch_id, room_no, capacity, building, document) VALUES (?, ?, ?, ?, NULL)",
            (branch_id, room_no, capacity, building),
        )
    conn.commit()

    # --- Syllabus ---
    syllabus_rows = [
        ("Mathematics", "Grade 10 - Term 1", 6),
        ("Physics", "Grade 10 - Term 1", 5),
        ("Chemistry", "Grade 10 - Term 1", 5),
        ("English", "Grade 10 - Term 1", 4),
        ("Computer Science", "Grade 10 - Term 1", 4),
    ]
    for subject, semester, units in syllabus_rows:
        cursor.execute(
            "INSERT INTO syllabus (branch_id, subject, semester, units, document) VALUES (?, ?, ?, ?, NULL)",
            (branch_id, subject, semester, units),
        )
    conn.commit()

    # --- Students (two batches, so the timetable/conflict demo has something to show) ---
    batch_a_students = [
        "Aarav Sharma", "Diya Patel", "Rohan Mehta", "Ishita Singh",
        "Kabir Reddy", "Ananya Rao", "Vivaan Gupta", "Sneha Kulkarni",
    ]
    batch_b_students = [
        "Arjun Nair", "Priya Menon", "Karan Malhotra", "Riya Chatterjee",
        "Aditya Bose", "Meera Pillai", "Yash Agarwal", "Tanvi Shah",
    ]
    all_students = []
    for i, name in enumerate(batch_a_students):
        email = name.lower().replace(" ", ".") + "@horizonschool.edu"
        cursor.execute(
            "INSERT INTO students (branch_id, name, email, course, status, document) VALUES (?, ?, ?, ?, ?, NULL)",
            (branch_id, name, email, "Grade 10 - A", "Active"),
        )
        all_students.append((name, "Grade 10 - A"))
    for name in batch_b_students:
        email = name.lower().replace(" ", ".") + "@horizonschool.edu"
        cursor.execute(
            "INSERT INTO students (branch_id, name, email, course, status, document) VALUES (?, ?, ?, ?, ?, NULL)",
            (branch_id, name, email, "Grade 10 - B", "Active"),
        )
        all_students.append((name, "Grade 10 - B"))
    conn.commit()

    # --- Attendance (a few days' worth, mostly present with some absences) ---
    sample_dates = ["2026-08-28", "2026-08-29", "2026-08-31"]
    for date in sample_dates:
        for idx, (name, _) in enumerate(all_students):
            status = "Absent" if (idx + hash(date)) % 7 == 0 else "Present"
            cursor.execute(
                "INSERT INTO attendance (branch_id, student_name, date, status, document) VALUES (?, ?, ?, ?, NULL)",
                (branch_id, name, date, status),
            )
    conn.commit()

    # --- Fees (mix of paid, pending, and overdue so the Fees module has something to demo) ---
    fee_plan = [
        ("Paid", "2026-07-15"),
        ("Paid", "2026-07-15"),
        ("Pending", "2026-09-15"),
        ("Pending", "2026-09-05"),   # due soon - demonstrates the reminder use case
        ("Overdue", "2026-08-20"),   # already past due
    ]
    for idx, (name, _) in enumerate(all_students):
        status, due_date = fee_plan[idx % len(fee_plan)]
        cursor.execute(
            "INSERT INTO fees (branch_id, student_name, amount_inr, status, due_date, document) VALUES (?, ?, ?, ?, ?, NULL)",
            (branch_id, name, 45000, status, due_date),
        )
    conn.commit()

    # --- Invigilator duty (sample exam roster) ---
    invigilation_rows = [
        ("Dr. Ramesh Kumar", "2026-09-15", "Room 101"),
        ("Mrs. Anjali Verma", "2026-09-15", "Room 102"),
        ("Mr. Suresh Iyer", "2026-09-16", "Room 201"),
    ]
    for teacher_name, exam_date, room in invigilation_rows:
        cursor.execute(
            "INSERT INTO invigilation (branch_id, teacher_name, exam_date, room, document) VALUES (?, ?, ?, ?, NULL)",
            (branch_id, teacher_name, exam_date, room),
        )
    conn.commit()

    # --- Timetable: generate real, conflict-checked schedules for both batches ---
    # Deliberately overlapping teachers across batches so the demo visibly proves
    # the double-booking fix (same teacher, different batches, no clashing slots).
    timings = [
        "09:00 AM - 10:00 AM", "10:00 AM - 11:00 AM",
        "11:15 AM - 12:15 PM", "01:15 PM - 02:15 PM",
    ]
    batch_a_config = [
        {"name": "Dr. Ramesh Kumar", "subject": "Mathematics", "lectures_per_week": 4, "unavailable_days": []},
        {"name": "Mrs. Anjali Verma", "subject": "Physics", "lectures_per_week": 3, "unavailable_days": []},
        {"name": "Ms. Priya Nair", "subject": "English", "lectures_per_week": 3, "unavailable_days": ["Friday"]},
    ]
    batch_b_config = [
        {"name": "Dr. Ramesh Kumar", "subject": "Mathematics", "lectures_per_week": 4, "unavailable_days": []},
        {"name": "Mr. Suresh Iyer", "subject": "Chemistry", "lectures_per_week": 3, "unavailable_days": []},
        {"name": "Mr. Vikram Joshi", "subject": "Computer Science", "lectures_per_week": 2, "unavailable_days": []},
    ]
    run_timetable_generation(conn, branch_id, "Grade 10 - A", batch_a_config, timings)
    run_timetable_generation(conn, branch_id, "Grade 10 - B", batch_b_config, timings)
    conn.commit()
    conn.close()

    return {
        "status": "demo account ready",
        "login_email": DEMO_EMAIL,
        "login_password": DEMO_PASSWORD,
        "note": "Log in at the site's homepage with these credentials. Re-run this endpoint anytime to reset the demo to a clean slate.",
    }


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def read_root():
    return HTMLResponse(content=HTML_CONTENT, status_code=200)


HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ALGORITHMIC - Enterprise Institutional Operations</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=Playfair+Display:ital,wght@0,600;1,600&display=swap');

        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: #070707;
            background-image:
                radial-gradient(rgba(212, 175, 55, 0.05) 1.5px, transparent 1.5px),
                radial-gradient(rgba(212, 175, 55, 0.02) 1.5px, #070707 1.5px);
            background-size: 40px 40px;
            background-position: 0 0, 20px 20px;
            color: #f3f4f6;
            overflow-x: hidden;
        }

        .elegant-font { font-family: 'Playfair Display', serif; }

        .gold-gradient-text {
            background: linear-gradient(135deg, #BF953F 0%, #FCF6BA 25%, #B38728 50%, #FBF5B7 75%, #AA771C 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .gold-border { border-color: rgba(212, 175, 55, 0.22); }

        .gold-border-glow:focus, .gold-border-glow:hover {
            border-color: #D4AF37;
            box-shadow: 0 0 10px rgba(212, 175, 55, 0.15);
        }

        .gold-bg { background: linear-gradient(135deg, #D4AF37, #AA771C); }

        .glass-panel {
            background: rgba(13, 13, 13, 0.85);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(212, 175, 55, 0.15);
        }

        .sidebar-item { transition: all 0.2s ease; letter-spacing: 0.06em; }
        .sidebar-item:hover, .sidebar-item.active {
            background: rgba(212, 175, 55, 0.1);
            color: #D4AF37;
            border-left: 3px solid #D4AF37;
            padding-left: 1.75rem;
        }

        .fast-transition { transition: all 0.15s ease-in-out; }

        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: #0a0a0a; }
        ::-webkit-scrollbar-thumb { background: #332d16; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #D4AF37; }

        .auth-error { color: #f87171; font-size: 11px; margin-top: 6px; min-height: 14px; }
    </style>
</head>
<body class="min-h-screen flex flex-col">

    <!-- LOGIN / SIGNUP SCREEN OVERLAY -->
    <div id="authOverlay" class="fixed inset-0 z-50 bg-[#050505] flex items-center justify-center p-4">
        <div class="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(212,175,55,0.06)_0,transparent_70%)]"></div>
        <div class="glass-panel w-full max-w-md p-8 rounded-2xl shadow-2xl relative z-10 border gold-border">
            <div class="text-center mb-8">
                <div class="inline-block p-3 rounded-full bg-[#121212] border gold-border mb-4 shadow-lg">
                    <span class="text-2xl font-black gold-gradient-text">⚡</span>
                </div>
                <h1 class="text-2xl font-black gold-gradient-text tracking-wider">ALGORITHMIC</h1>
                <p class="text-xs text-gray-400 mt-1 uppercase tracking-widest">Enterprise Institutional Portal</p>
            </div>

            <!-- LOGIN FORM -->
            <form id="loginForm" onsubmit="handleLogin(event)" class="space-y-5">
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Email</label>
                    <input type="email" id="loginEmail" required placeholder="admin@institute.edu" class="w-full bg-[#0c0c0c] border gold-border rounded-xl px-4 py-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Password</label>
                    <input type="password" id="loginPassword" required placeholder="••••••••••••" class="w-full bg-[#0c0c0c] border gold-border rounded-xl px-4 py-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                </div>
                <div id="loginError" class="auth-error"></div>
                <button type="submit" class="w-full gold-bg hover:opacity-95 text-black font-extrabold py-3.5 rounded-xl text-sm fast-transition shadow-lg tracking-wider uppercase">
                    Log In
                </button>
                <p class="text-center text-xs text-gray-500 pt-2">New institute? <a href="#" onclick="showSignup(event)" class="gold-gradient-text font-semibold hover:underline">Create an account</a></p>
            </form>

            <!-- SIGNUP FORM -->
            <form id="signupForm" onsubmit="handleSignup(event)" class="space-y-4 hidden">
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Institute Name</label>
                    <input type="text" id="signupInstitute" required placeholder="Algorithmic Academy of Excellence" class="w-full bg-[#0c0c0c] border gold-border rounded-xl px-4 py-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Your Name</label>
                    <input type="text" id="signupName" required placeholder="Samarth Dave" class="w-full bg-[#0c0c0c] border gold-border rounded-xl px-4 py-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Email</label>
                    <input type="email" id="signupEmail" required placeholder="admin@institute.edu" class="w-full bg-[#0c0c0c] border gold-border rounded-xl px-4 py-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                </div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Password (min 8 characters)</label>
                    <input type="password" id="signupPassword" required minlength="8" placeholder="••••••••••••" class="w-full bg-[#0c0c0c] border gold-border rounded-xl px-4 py-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                </div>
                <div id="signupError" class="auth-error"></div>
                <button type="submit" class="w-full gold-bg hover:opacity-95 text-black font-extrabold py-3.5 rounded-xl text-sm fast-transition shadow-lg tracking-wider uppercase">
                    Create Account
                </button>
                <p class="text-center text-xs text-gray-500 pt-2">Already registered? <a href="#" onclick="showLogin(event)" class="gold-gradient-text font-semibold hover:underline">Log in</a></p>
            </form>

            <div class="mt-8 pt-6 border-t gold-border text-center text-xs text-gray-500 space-y-1">
                <p class="font-semibold text-gray-400">CREATED BY SAMARTH DAVE</p>
                <p>FOUNDER OF <a href="https://machsevenstudios-website.onrender.com" target="_blank" class="gold-gradient-text hover:underline font-semibold">MACHSEVENSTUDIOS</a></p>
                <p class="text-[10px] text-yellow-600/80 tracking-widest uppercase pt-1">POWERED BY METASYS<sup>®</sup></p>
            </div>
        </div>
    </div>

    <!-- MAIN APP CONTAINER -->
    <div id="appContainer" class="min-h-screen flex flex-col hidden">
        <header class="border-b gold-border bg-[#0a0a0a]/95 backdrop-blur-md px-8 py-4 flex justify-between items-center sticky top-0 z-40">
            <div class="flex items-center space-x-6">
                <h1 class="text-xl font-black gold-gradient-text tracking-wider">ALGORITHMIC</h1>
                <div class="h-5 w-[1px] bg-yellow-600/30"></div>
                <div class="flex items-center space-x-2">
                    <span class="text-xs uppercase tracking-widest text-gray-400">Institute:</span>
                    <span id="headerInstituteName" class="text-sm font-bold text-gray-200 tracking-wide bg-[#141414] px-3 py-1 rounded-lg border gold-border">—</span>
                </div>
            </div>
            <div class="flex items-center space-x-6 text-sm">
                <div class="flex items-center space-x-2 bg-[#121212] px-3 py-1.5 rounded-lg border gold-border">
                    <span class="text-xs text-gray-400">Active Branch:</span>
                    <select id="branchSelector" class="bg-transparent text-sm font-semibold gold-gradient-text focus:outline-none cursor-pointer"></select>
                    <button onclick="openAddBranchModal()" class="ml-2 text-xs bg-[#1a1a1a] hover:bg-[#252525] gold-gradient-text border gold-border px-2 py-0.5 rounded fast-transition">+ Branch</button>
                </div>
                <div class="text-xs text-right border-l pl-6 gold-border">
                    <div class="text-gray-400">Logged in as</div>
                    <div id="headerFullName" class="font-bold gold-gradient-text">—</div>
                </div>
                <button onclick="handleLogout()" class="text-xs bg-[#161616] hover:bg-[#222] text-red-400 border border-red-900/40 px-3 py-2 rounded-lg fast-transition">Logout</button>
            </div>
        </header>

        <div class="flex flex-1 overflow-hidden">
            <nav class="w-72 border-r gold-border bg-[#0b0b0b] flex flex-col py-6 space-y-1.5 shrink-0">
                <div class="px-6 pb-2 text-[11px] font-bold text-gray-500 uppercase tracking-widest">Enterprise Modules</div>
                <button onclick="switchModule('home')" class="sidebar-item active w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>⚡</span><span>Home Dashboard</span></button>
                <button onclick="switchModule('students')" class="sidebar-item w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>🎓</span><span>Students</span></button>
                <button onclick="switchModule('teachers')" class="sidebar-item w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>👨‍🏫</span><span>Teachers</span></button>
                <button onclick="switchModule('classrooms')" class="sidebar-item w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>🏛️</span><span>Classrooms</span></button>
                <button onclick="switchModule('syllabus')" class="sidebar-item w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>📚</span><span>Syllabus</span></button>
                <button onclick="switchModule('attendance')" class="sidebar-item w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>📋</span><span>Attendance</span></button>
                <button onclick="switchModule('timetables')" class="sidebar-item w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>🕒</span><span>Timetable</span></button>
                <button onclick="switchModule('invigilation')" class="sidebar-item w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>🛡️</span><span>Invigilator Duty</span></button>
                <button onclick="switchModule('fees')" class="sidebar-item w-full text-left px-6 py-3 text-xs font-extrabold uppercase text-gray-300 flex items-center space-x-3"><span>💳</span><span>Fees (INR ₹)</span></button>

                <div class="mt-auto px-6 pt-6 border-t gold-border text-[11px] text-gray-400 space-y-1 bg-[#090909]">
                    <p class="elegant-font text-sm gold-gradient-text tracking-wide">created by Samarth Dave</p>
                    <p class="text-gray-300">Founder of <a href="https://machsevenstudios-website.onrender.com" target="_blank" class="gold-gradient-text hover:underline">MachSevenStudios</a></p>
                    <p class="text-[10px] text-yellow-600 font-bold uppercase tracking-widest pt-1">Powered by Metasys<sup>®</sup></p>
                </div>
            </nav>

            <main class="flex-1 p-10 overflow-y-auto bg-[#070707]" id="mainContent"></main>
        </div>
    </div>

    <!-- Generic Add Record Modal -->
    <div id="recordModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center hidden z-50">
        <div class="glass-panel border gold-border p-8 rounded-2xl w-full max-w-lg shadow-2xl">
            <div class="flex justify-between items-center mb-6">
                <h3 id="modalTitle" class="text-lg font-extrabold gold-gradient-text uppercase tracking-wider">Add Record</h3>
                <button onclick="closeRecordModal()" class="text-gray-400 hover:text-white text-lg font-bold">✕</button>
            </div>
            <form id="recordForm" onsubmit="submitRecordForm(event)" class="space-y-4">
                <div id="modalFields" class="space-y-4"></div>
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1.5">Attach Document (PDF/JPG/PNG/DOC, max 5MB)</label>
                    <input type="file" id="recordFile" accept=".pdf,.jpg,.jpeg,.png,.doc,.docx" class="w-full bg-[#0c0c0c] border gold-border rounded-xl p-2.5 text-xs text-gray-300 file:mr-4 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-[#221c0c] file:text-yellow-500 hover:file:bg-[#332a0f]">
                </div>
                <div id="recordFormError" class="auth-error"></div>
                <div class="flex justify-end space-x-3 pt-4 border-t gold-border">
                    <button type="button" onclick="closeRecordModal()" class="px-5 py-2.5 text-xs font-bold uppercase bg-gray-900 hover:bg-gray-800 text-gray-300 rounded-xl fast-transition">Cancel</button>
                    <button type="submit" class="px-6 py-2.5 text-xs font-extrabold uppercase gold-bg hover:opacity-95 text-black rounded-xl fast-transition shadow-lg">Save Record</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Add Branch Modal -->
    <div id="branchModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center hidden z-50">
        <div class="glass-panel border gold-border p-8 rounded-2xl w-full max-w-md shadow-2xl">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-lg font-extrabold gold-gradient-text uppercase tracking-wider">Add Branch</h3>
                <button onclick="closeAddBranchModal()" class="text-gray-400 hover:text-white text-lg font-bold">✕</button>
            </div>
            <div class="space-y-4">
                <input type="text" id="newBranchName" placeholder="e.g. North Campus - Pune" class="w-full bg-[#0c0c0c] border gold-border rounded-xl px-4 py-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                <button onclick="createNewBranch()" class="w-full gold-bg hover:opacity-95 text-black font-extrabold py-3 rounded-xl text-xs uppercase tracking-wider fast-transition shadow-lg">Create Branch</button>
            </div>
        </div>
    </div>

    <script>
        let branches = [];
        let currentBranchId = null;
        let currentModule = 'home';
        let authToken = localStorage.getItem('algorithmic_token');

        // ---- Auth ----

        function showSignup(e) { e.preventDefault(); document.getElementById('loginForm').classList.add('hidden'); document.getElementById('signupForm').classList.remove('hidden'); }
        function showLogin(e) { e.preventDefault(); document.getElementById('signupForm').classList.add('hidden'); document.getElementById('loginForm').classList.remove('hidden'); }

        async function handleLogin(e) {
            e.preventDefault();
            const errorEl = document.getElementById('loginError');
            errorEl.textContent = '';
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();
                if (!res.ok) { errorEl.textContent = data.detail || 'Login failed.'; return; }
                completeAuth(data);
            } catch (err) { errorEl.textContent = 'Network error. Please try again.'; }
        }

        async function handleSignup(e) {
            e.preventDefault();
            const errorEl = document.getElementById('signupError');
            errorEl.textContent = '';
            const institute_name = document.getElementById('signupInstitute').value;
            const full_name = document.getElementById('signupName').value;
            const email = document.getElementById('signupEmail').value;
            const password = document.getElementById('signupPassword').value;
            try {
                const res = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ institute_name, full_name, email, password })
                });
                const data = await res.json();
                if (!res.ok) { errorEl.textContent = data.detail || 'Signup failed.'; return; }
                completeAuth(data);
            } catch (err) { errorEl.textContent = 'Network error. Please try again.'; }
        }

        function completeAuth(data) {
            authToken = data.token;
            localStorage.setItem('algorithmic_token', authToken);
            document.getElementById('headerInstituteName').textContent = data.institute_name;
            document.getElementById('headerFullName').textContent = data.full_name || data.institute_name;
            document.getElementById('authOverlay').classList.add('hidden');
            document.getElementById('appContainer').classList.remove('hidden');
            initApp();
        }

        async function handleLogout() {
            try { await authFetch('/api/auth/logout', { method: 'POST' }); } catch (e) {}
            localStorage.removeItem('algorithmic_token');
            authToken = null;
            currentBranchId = null;
            document.getElementById('appContainer').classList.add('hidden');
            document.getElementById('authOverlay').classList.remove('hidden');
            document.getElementById('loginForm').classList.remove('hidden');
            document.getElementById('signupForm').classList.add('hidden');
        }

        // Wraps fetch to attach the auth token and bounce to login on 401.
        async function authFetch(url, options = {}) {
            options.headers = options.headers || {};
            options.headers['Authorization'] = `Bearer ${authToken}`;
            const res = await fetch(url, options);
            if (res.status === 401) {
                localStorage.removeItem('algorithmic_token');
                authToken = null;
                document.getElementById('appContainer').classList.add('hidden');
                document.getElementById('authOverlay').classList.remove('hidden');
                document.getElementById('loginError').textContent = 'Session expired. Please log in again.';
                throw new Error('Session expired');
            }
            return res;
        }

        // Try to resume a session on page load if a token is already saved.
        (async function tryResumeSession() {
            if (!authToken) return;
            try {
                const res = await authFetch('/api/branches');
                if (res.ok) {
                    // We don't have a dedicated "who am I" endpoint response with names here,
                    // so pull them from the first branches call context via a lightweight ping.
                    document.getElementById('authOverlay').classList.add('hidden');
                    document.getElementById('appContainer').classList.remove('hidden');
                    initApp();
                }
            } catch (e) { /* handled in authFetch */ }
        })();

        // ---- Branches ----

        async function loadBranches() {
            const res = await authFetch('/api/branches');
            branches = await res.json();
            const selector = document.getElementById('branchSelector');
            selector.innerHTML = '';
            branches.forEach(b => {
                const opt = document.createElement('option');
                opt.value = b.id;
                opt.textContent = b.name;
                if (currentBranchId === b.id) opt.selected = true;
                selector.appendChild(opt);
            });
            if (!currentBranchId && branches.length > 0) {
                currentBranchId = branches[0].id;
                selector.value = currentBranchId;
            }
        }

        document.getElementById('branchSelector').addEventListener('change', (e) => {
            currentBranchId = parseInt(e.target.value);
            refreshCurrentModule();
        });

        function openAddBranchModal() { document.getElementById('branchModal').classList.remove('hidden'); }
        function closeAddBranchModal() { document.getElementById('branchModal').classList.add('hidden'); document.getElementById('newBranchName').value = ''; }

        async function createNewBranch() {
            const name = document.getElementById('newBranchName').value.trim();
            if (!name) return;
            const res = await authFetch('/api/branches', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            if (res.ok) {
                const newBranch = await res.json();
                closeAddBranchModal();
                await loadBranches();
                currentBranchId = newBranch.id;
                document.getElementById('branchSelector').value = currentBranchId;
                refreshCurrentModule();
            } else {
                alert('Branch already exists or invalid name.');
            }
        }

        function switchModule(moduleName) {
            currentModule = moduleName;
            document.querySelectorAll('.sidebar-item').forEach(btn => btn.classList.remove('active'));
            event.currentTarget.classList.add('active');
            refreshCurrentModule();
        }

        async function initApp() {
            await loadBranches();
            refreshCurrentModule();
        }

        async function refreshCurrentModule() {
            const container = document.getElementById('mainContent');
            if (currentModule === 'home') {
                renderHomeModule(container);
            } else if (currentModule === 'timetables') {
                renderTimetableModule(container);
            } else {
                await renderDataModule(container, currentModule);
            }
        }

        function renderHomeModule(container) {
            container.innerHTML = `
                <div class="space-y-8">
                    <div class="glass-panel border gold-border p-10 rounded-3xl relative overflow-hidden shadow-2xl">
                        <div class="max-w-3xl relative z-10 space-y-4">
                            <span class="text-xs uppercase tracking-widest px-3 py-1 rounded-full bg-[#1c1c1c] gold-gradient-text border gold-border font-extrabold">Executive Command Center</span>
                            <h2 class="text-4xl font-black text-white tracking-tight leading-tight">Institutional Operations, <span class="gold-gradient-text">Mastered.</span></h2>
                            <p class="text-lg text-gray-300 font-medium leading-relaxed pt-2">We simplify the boring clerical work. Not by hiring more clerks, but by never needing to do so.</p>
                            <div class="pt-4 flex items-center space-x-4">
                                <button onclick="switchModule('students')" class="gold-bg hover:opacity-95 text-black font-extrabold px-6 py-3 rounded-xl text-xs uppercase tracking-wider fast-transition shadow-lg">Manage Students</button>
                                <button onclick="switchModule('fees')" class="bg-[#141414] hover:bg-[#1f1f1f] gold-gradient-text border gold-border font-extrabold px-6 py-3 rounded-xl text-xs uppercase tracking-wider fast-transition">View Fees (INR ₹)</button>
                            </div>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                        <div class="glass-panel p-6 rounded-2xl border gold-border"><div class="text-gray-400 text-xs uppercase tracking-widest mb-1">Active Students</div><div class="text-3xl font-black gold-gradient-text" id="statStudents">—</div></div>
                        <div class="glass-panel p-6 rounded-2xl border gold-border"><div class="text-gray-400 text-xs uppercase tracking-widest mb-1">Faculty Members</div><div class="text-3xl font-black gold-gradient-text" id="statTeachers">—</div></div>
                        <div class="glass-panel p-6 rounded-2xl border gold-border"><div class="text-gray-400 text-xs uppercase tracking-widest mb-1">Classrooms Available</div><div class="text-3xl font-black gold-gradient-text" id="statClassrooms">—</div></div>
                        <div class="glass-panel p-6 rounded-2xl border gold-border"><div class="text-gray-400 text-xs uppercase tracking-widest mb-1">Fee Collection (INR)</div><div class="text-3xl font-black gold-gradient-text" id="statFees">₹0</div></div>
                    </div>
                </div>
            `;
            loadHomeStats();
        }

        async function loadHomeStats() {
            try {
                if (!currentBranchId) return;
                const [sRes, tRes, cRes, fRes] = await Promise.all([
                    authFetch(`/api/records/students/${currentBranchId}`),
                    authFetch(`/api/records/teachers/${currentBranchId}`),
                    authFetch(`/api/records/classrooms/${currentBranchId}`),
                    authFetch(`/api/records/fees/${currentBranchId}`)
                ]);
                document.getElementById('statStudents').textContent = (await sRes.json()).length;
                document.getElementById('statTeachers').textContent = (await tRes.json()).length;
                document.getElementById('statClassrooms').textContent = (await cRes.json()).length;
                const fees = await fRes.json();
                const total = fees.reduce((acc, curr) => acc + (curr.amount_inr || 0), 0);
                document.getElementById('statFees').textContent = `₹${total.toLocaleString('en-IN')}`;
            } catch (e) { console.error(e); }
        }

        async function renderDataModule(container, moduleName) {
            container.innerHTML = `
                <div class="space-y-6">
                    <div class="flex justify-between items-center">
                        <div>
                            <h2 class="text-2xl font-black uppercase gold-gradient-text tracking-wide">${moduleName} Department</h2>
                            <p class="text-xs text-gray-400 mt-1 uppercase tracking-widest">Branch Synchronized • Document Supported</p>
                        </div>
                        <button onclick="openRecordModal('${moduleName}')" class="gold-bg hover:opacity-95 text-black font-extrabold px-5 py-2.5 rounded-xl text-xs uppercase tracking-wider fast-transition shadow-lg flex items-center space-x-2"><span>+ Add New Record</span></button>
                    </div>
                    <div class="glass-panel border gold-border rounded-2xl p-6 overflow-x-auto shadow-2xl">
                        <table class="w-full text-left text-sm text-gray-300">
                            <thead id="moduleTableHead" class="bg-[#121212] text-xs uppercase gold-gradient-text border-b gold-border"></thead>
                            <tbody id="moduleTableBody"></tbody>
                        </table>
                    </div>
                </div>
            `;
            await loadModuleRecords(moduleName);
        }

        async function loadModuleRecords(moduleName) {
            if (!currentBranchId) return;
            const res = await authFetch(`/api/records/${moduleName}/${currentBranchId}`);
            const records = await res.json();
            const thead = document.getElementById('moduleTableHead');
            const tbody = document.getElementById('moduleTableBody');

            if (records.length === 0) {
                thead.innerHTML = `<tr><th class="p-4">Status</th></tr>`;
                tbody.innerHTML = `<tr><td class="p-8 text-center text-gray-500">No records found for ${moduleName}. Click '+ Add New Record' to create one.</td></tr>`;
                return;
            }

            const keys = Object.keys(records[0]).filter(k => k !== 'id' && k !== 'branch_id');
            thead.innerHTML = `<tr>${keys.map(k => `<th class="p-4 uppercase tracking-wider text-xs font-bold">${k.replace('_', ' ')}</th>`).join('')}</tr>`;
            tbody.innerHTML = records.map(r => `
                <tr class="border-b border-gray-900 hover:bg-[#121212] fast-transition">
                    ${keys.map(k => {
                        let val = r[k];
                        if (moduleName === 'fees' && k === 'amount_inr') { val = `₹${parseFloat(val || 0).toLocaleString('en-IN')}`; }
                        if (k === 'document' && val) { val = `<a href="/uploads/${val}" target="_blank" class="text-yellow-500 underline text-xs font-semibold">View File</a>`; }
                        else if (k === 'document' && !val) { val = `<span class="text-gray-600 text-xs">No File</span>`; }
                        return `<td class="p-4 font-medium">${val}</td>`;
                    }).join('')}
                </tr>
            `).join('');
        }

        async function renderTimetableModule(container) {
            const tRes = await authFetch(`/api/records/teachers/${currentBranchId}`);
            const teachers = await tRes.json();
            const sRes = await authFetch(`/api/timetable/slots/${currentBranchId}`);
            const savedSlots = await sRes.json();

            container.innerHTML = `
                <div class="space-y-8">
                    <div class="flex justify-between items-center">
                        <div>
                            <h2 class="text-2xl font-black uppercase gold-gradient-text tracking-wide">Timetable Generation & Batch Scheduler</h2>
                            <p class="text-xs text-gray-400 mt-1 uppercase tracking-widest">Conflict-checked scheduler (teacher & room aware)</p>
                        </div>
                        <button onclick="window.print()" class="bg-[#141414] hover:bg-[#202020] gold-gradient-text border gold-border px-5 py-2.5 rounded-xl text-xs font-extrabold uppercase tracking-wider fast-transition shadow-lg">Download PDF / Print Timetable</button>
                    </div>
                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        <div class="glass-panel border gold-border p-6 rounded-2xl space-y-6">
                            <h3 class="text-sm font-extrabold gold-gradient-text uppercase tracking-wider">Configure Batch & Teacher Load</h3>
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Batch Name</label>
                                    <input type="text" id="ttBatchName" placeholder="e.g. B.Tech CSE Batch A" value="B.Tech CSE Batch A" class="w-full bg-[#0c0c0c] border gold-border rounded-xl p-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                                </div>
                                <div>
                                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Lecture Timings (Comma separated)</label>
                                    <input type="text" id="ttTimings" value="09:00 AM - 10:00 AM, 10:00 AM - 11:00 AM, 11:15 AM - 12:15 PM, 01:15 PM - 02:15 PM" class="w-full bg-[#0c0c0c] border gold-border rounded-xl p-3 text-xs text-gray-200 gold-border-glow focus:outline-none">
                                </div>
                                <div class="pt-2">
                                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Assigned Teachers & Constraints</label>
                                    <div id="teacherConfigList" class="space-y-3 max-h-60 overflow-y-auto pr-2">
                                        ${teachers.length === 0 ? '<p class="text-xs text-gray-500">No teachers found. Please add teachers first.</p>' :
                                          teachers.map((t, idx) => `
                                            <div class="p-3 bg-[#0f0f0f] border gold-border rounded-xl space-y-2" data-teacher="${t.name}" data-subject="${t.subject}">
                                                <div class="flex justify-between items-center text-xs font-bold text-gray-200"><span>${t.name} (${t.subject})</span></div>
                                                <div class="grid grid-cols-2 gap-2">
                                                    <div><label class="text-[10px] text-gray-400 uppercase">Lectures/Week</label><input type="number" id="lec_${idx}" value="3" min="1" max="5" class="w-full bg-[#070707] border gold-border rounded p-1.5 text-xs text-white"></div>
                                                    <div><label class="text-[10px] text-gray-400 uppercase">Unavailable Days</label><input type="text" id="unav_${idx}" placeholder="e.g. Monday" class="w-full bg-[#070707] border gold-border rounded p-1.5 text-xs text-white" title="Comma separated days"></div>
                                                </div>
                                            </div>
                                          `).join('')}
                                    </div>
                                </div>
                                <button onclick="generateTimetableSchedule()" class="w-full gold-bg hover:opacity-95 text-black font-extrabold py-3 rounded-xl text-xs uppercase tracking-wider fast-transition shadow-lg">Generate Weekly Timetable</button>
                            </div>
                        </div>
                        <div class="lg:col-span-2 glass-panel border gold-border p-6 rounded-2xl overflow-x-auto">
                            <h3 class="text-sm font-extrabold gold-gradient-text uppercase tracking-wider mb-4">Generated Weekly Schedule</h3>
                            <table class="w-full text-left text-sm text-gray-300">
                                <thead class="bg-[#121212] text-xs uppercase gold-gradient-text border-b gold-border"><tr><th class="p-3">Day</th><th class="p-3">Time Slot</th><th class="p-3">Subject</th><th class="p-3">Teacher</th><th class="p-3">Room</th></tr></thead>
                                <tbody id="timetableSlotsBody">
                                    ${savedSlots.length === 0 ? '<tr><td colspan="5" class="p-6 text-center text-gray-500">No timetable generated yet. Configure and click generate.</td></tr>' :
                                      savedSlots.map(s => `
                                        <tr class="border-b border-gray-900 hover:bg-[#121212] fast-transition">
                                            <td class="p-3 font-semibold text-yellow-500">${s.day}</td><td class="p-3">${s.time_slot}</td><td class="p-3 font-medium">${s.subject}</td><td class="p-3">${s.teacher}</td><td class="p-3 text-xs text-gray-400">${s.room}</td>
                                        </tr>
                                      `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
        }

        async function generateTimetableSchedule() {
            const batchName = document.getElementById('ttBatchName').value;
            const timingsRaw = document.getElementById('ttTimings').value;
            const timings = timingsRaw.split(',').map(s => s.trim()).filter(Boolean);
            const teacherElements = document.querySelectorAll('#teacherConfigList > div');
            const teachers_config = [];
            teacherElements.forEach((el, idx) => {
                const name = el.getAttribute('data-teacher');
                const subject = el.getAttribute('data-subject');
                const lectures_per_week = document.getElementById(`lec_${idx}`).value;
                const unavRaw = document.getElementById(`unav_${idx}`).value;
                const unavailable_days = unavRaw.split(',').map(s => s.trim()).filter(Boolean);
                teachers_config.push({ name, subject, lectures_per_week, unavailable_days });
            });

            const res = await authFetch('/api/timetable/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ branch_id: currentBranchId, batch_name: batchName, teachers_config, timings })
            });

            if (res.ok) {
                const result = await res.json();
                let msg = 'Timetable successfully generated and saved!';
                if (result.warnings && result.warnings.length > 0) {
                    msg += '\\n\\nHeads up:\\n' + result.warnings.join('\\n');
                }
                alert(msg);
                refreshCurrentModule();
            } else {
                alert('Failed to generate timetable.');
            }
        }

        function openRecordModal(moduleName) {
            document.getElementById('recordModal').classList.remove('hidden');
            document.getElementById('modalTitle').textContent = `Add New ${moduleName} Record`;
            document.getElementById('recordFormError').textContent = '';
            const fieldsContainer = document.getElementById('modalFields');
            document.getElementById('recordFile').value = '';

            let fieldsConfig = [];
            if (moduleName === 'students') {
                fieldsConfig = [
                    { id: 'name', label: 'Full Name', type: 'text', placeholder: 'Aarav Sharma' },
                    { id: 'email', label: 'Email Address', type: 'email', placeholder: 'aarav@institution.edu' },
                    { id: 'course', label: 'Course / Program', type: 'text', placeholder: 'B.Tech Computer Science' },
                    { id: 'status', label: 'Status', type: 'text', placeholder: 'Active' }
                ];
            } else if (moduleName === 'teachers') {
                fieldsConfig = [
                    { id: 'name', label: 'Teacher Name', type: 'text', placeholder: 'Dr. Ramesh Kumar' },
                    { id: 'subject', label: 'Specialization', type: 'text', placeholder: 'Artificial Intelligence' },
                    { id: 'department', label: 'Department', type: 'text', placeholder: 'School of Engineering' }
                ];
            } else if (moduleName === 'classrooms') {
                fieldsConfig = [
                    { id: 'room_no', label: 'Room Number', type: 'text', placeholder: 'Lecture Hall 402' },
                    { id: 'capacity', label: 'Seating Capacity', type: 'number', placeholder: '120' },
                    { id: 'building', label: 'Building Name', type: 'text', placeholder: 'Apex Tower' }
                ];
            } else if (moduleName === 'syllabus') {
                fieldsConfig = [
                    { id: 'subject', label: 'Subject Name', type: 'text', placeholder: 'Data Structures & Algorithms' },
                    { id: 'semester', label: 'Semester', type: 'text', placeholder: 'Fall 2026' },
                    { id: 'units', label: 'Credit Units', type: 'number', placeholder: '4' }
                ];
            } else if (moduleName === 'attendance') {
                fieldsConfig = [
                    { id: 'student_name', label: 'Student Name', type: 'text', placeholder: 'Priya Patel' },
                    { id: 'date', label: 'Date', type: 'text', placeholder: '2026-09-01' },
                    { id: 'status', label: 'Attendance Status', type: 'text', placeholder: 'Present' }
                ];
            } else if (moduleName === 'invigilation') {
                fieldsConfig = [
                    { id: 'teacher_name', label: 'Faculty Name', type: 'text', placeholder: 'Prof. Vikram Joshi' },
                    { id: 'exam_date', label: 'Exam Date', type: 'text', placeholder: '2026-09-15' },
                    { id: 'room', label: 'Exam Hall', type: 'text', placeholder: 'Examination Block B' }
                ];
            } else if (moduleName === 'fees') {
                fieldsConfig = [
                    { id: 'student_name', label: 'Student Name', type: 'text', placeholder: 'Rohan Sharma' },
                    { id: 'amount_inr', label: 'Fee Amount (INR ₹)', type: 'number', placeholder: '75000' },
                    { id: 'status', label: 'Payment Status', type: 'text', placeholder: 'Paid / Pending' },
                    { id: 'due_date', label: 'Due Date', type: 'text', placeholder: '2026-09-30' }
                ];
            }

            fieldsContainer.innerHTML = fieldsConfig.map(f => `
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1.5">${f.label}</label>
                    <input type="${f.type}" id="field_${f.id}" required placeholder="${f.placeholder}" class="w-full bg-[#0c0c0c] border gold-border rounded-xl p-3 text-sm text-gray-200 gold-border-glow focus:outline-none">
                </div>
            `).join('');

            window.activeModalModule = moduleName;
        }

        function closeRecordModal() { document.getElementById('recordModal').classList.add('hidden'); }

        async function submitRecordForm(e) {
            e.preventDefault();
            const errorEl = document.getElementById('recordFormError');
            errorEl.textContent = '';
            const moduleName = window.activeModalModule;
            const inputs = document.getElementById('modalFields').querySelectorAll('input');
            const data = {};
            inputs.forEach(input => { const key = input.id.replace('field_', ''); data[key] = input.type === 'number' ? parseFloat(input.value) : input.value; });

            const formData = new FormData();
            formData.append('branch_id', currentBranchId);
            formData.append('data_json', JSON.stringify(data));
            const fileInput = document.getElementById('recordFile');
            if (fileInput.files[0]) { formData.append('file', fileInput.files[0]); }

            const res = await authFetch(`/api/records/${moduleName}`, { method: 'POST', body: formData });

            if (res.ok) {
                closeRecordModal();
                await loadModuleRecords(moduleName);
            } else {
                const errData = await res.json().catch(() => ({}));
                errorEl.textContent = errData.detail || 'Failed to save record.';
            }
        }
    </script>
</body>
</html>
"""
