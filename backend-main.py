from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from gridfs import GridFS
import hashlib
import os

app = FastAPI()

# Allow local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient("mongodb://localhost:27017")
db = client["secure_vault"]
fs = GridFS(db)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

@app.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    if db.users.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    db.users.insert_one({"username": username, "password": hash_password(password)})
    return {"message": "User registered"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = db.users.find_one({"username": username})
    if not user or user["password"] != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # For simplicity, return username as token (use JWT in production!)
    return {"token": username}

@app.post("/upload")
def upload_file(token: str = Form(...), file: UploadFile = File(...)):
    user = db.users.find_one({"username": token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    contents = file.file.read()
    sha256 = hashlib.sha256(contents).hexdigest()
    file_id = fs.put(contents, filename=file.filename, owner=token, sha256=sha256)
    db.files.insert_one({"owner": token, "file_id": file_id, "filename": file.filename, "sha256": sha256})
    return {"message": "File uploaded", "sha256": sha256}

@app.get("/files")
def list_files(token: str):
    user = db.users.find_one({"username": token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    files = list(db.files.find({"owner": token}, {"filename": 1, "sha256": 1}))
    return files

# More endpoints: download, delete...
