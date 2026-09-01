from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# THIS IS THE MISSING VARIABLE:
app = FastAPI(title="Algorithmic Institutional Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "Algorithmic Backend is live!"}

@app.get("/api/records/{module}")
def get_records(module: str):
    return {"module": module, "data": []}
