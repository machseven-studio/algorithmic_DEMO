import os
import sqlite3
import hashlib
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

app = FastAPI(title="Algorithmic Institutional Platform")

# Enable CORS so your frontend can communicate with the backend smoothly
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "algorithmic_enterprise.db"


def get_db_connection():
    """
    Establishes a connection with a 30-second timeout 
    and enables Write-Ahead Logging (WAL) to prevent database locks.
    """
    conn = sqlite3.connect(DB_FILE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    # WAL mode drastically reduces "database is locked" errors during concurrent operations
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt.encode('utf-8'), 
        200000
    ).hex()
    return hashed, salt


VALID_MODULES = ["teachers", "classrooms", "invigilators", "defaulters"]


@app.get("/", response_class=HTMLResponse)
def serve_website():
    """
    Serves the index.html website UI directly at the root URL.
    """
    if not os.path.exists("index.html"):
        return HTMLResponse(
            content="<h1>index.html not found! Make sure index.html is in your repository root.</h1>", 
            status_code=404
        )
    with open("index.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


@app.get("/api/records/{module}")
def get_records(module: str, branch_id: Optional[str] = None):
    """
    API endpoint to fetch data for specific institutional modules.
    """
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module requested.")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Create table dynamically if it doesn't exist yet
        cursor.execute(f"CREATE TABLE IF NOT EXISTS {module} (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, details TEXT)")
        
        if branch_id:
            cursor.execute(f"SELECT * FROM {module} WHERE branch_id = ?", (branch_id,))
        else:
            cursor.execute(f"SELECT * FROM {module}")
            
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
