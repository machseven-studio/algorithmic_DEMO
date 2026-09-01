import os
import sqlite3
import hashlib
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

app = FastAPI(title="Algorithmic Institutional Backend")

# Enable CORS for frontend requests
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
    # WAL mode drastically reduces "database is locked" errors during concurrent writes
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

# Simple schema mapping for standard modules
VALID_MODULES = ["teachers", "classrooms", "invigilators", "defaulters"]

@app.get("/api/records/{module}")
def get_records(module: str, branch_id: Optional[str] = None):
    """
    Generic fetch route expected by your frontend.
    """
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module requested.")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Ensures table exists safely
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
