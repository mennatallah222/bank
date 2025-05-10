from datetime import datetime, timedelta
import os
from fastapi import APIRouter, Depends, Form, HTTPException, status
from markupsafe import Markup
from sqlalchemy import text
from sqlalchemy.orm import Session
from fastapi.responses import HTMLResponse
from app.database import get_db
from fastapi import Request
from fastapi.templating import Jinja2Templates
import requests
from urllib.parse import urlparse
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi.responses import RedirectResponse
from fastapi import File, UploadFile


router = APIRouter()

limiter = Limiter(key_func=get_remote_address)
pwd_context=CryptContext(schemes=["bcrypt"], deprecated="auto")
templates = Jinja2Templates(directory="app/views")

# #hardcoded credentials (A07: Identification and Authentication Failures)
# ADMIN_CREDENTIALS = {"username": "admin 1", "password": "aaa"}

@router.get("/", response_class=HTMLResponse)
async def read_root(req: Request):
    return templates.TemplateResponse("home.html", {"request": req})


@router.get("/register", response_class=HTMLResponse)
def get_register(req: Request):
    return templates.TemplateResponse("register.html", {"request": req})

@router.post("/register")
def post_register(username: str = Form(...),password: str = Form(...),role: str = Form(...),db: Session = Depends(get_db)):
    existing_user = db.execute(text("SELECT * FROM users WHERE username = :username"), {"username": username}).fetchone()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    db.execute(
    text("""
        INSERT INTO users (username, password, role, avatar_url) VALUES (:username, :password, :role, :avatar_url) """), {
        "username": username,
        "password": password,
        "role": role,
        "avatar_url": "https://img.freepik.com/free-vector/businessman-character-avatar-isolated_24877-60111.jpg?t=st=1746652457~exp=1746656057~hmac=e629c4a41bb033c9070818b13a8b98ff0eb9f6ac5070f1f06d536b82b5c1a71b&w=826"}
    )
    db.commit()

    user = db.execute(text("SELECT * FROM users WHERE username = :username AND password = :password"), {"username": username, "password": password}).fetchone()
    
    if user:
        user_id=user[0]
    response = RedirectResponse(url=f"/dashboard?user_id={user_id}", status_code=status.HTTP_302_FOUND)
    return response


@router.get("/login", response_class=HTMLResponse)
def get_login(req: Request):
    return templates.TemplateResponse("login.html", {"request": req})


ADMIN_USERNAME1 = "admin 1"
ADMIN_PASS1 ="aaa"

@router.post("/login")
@limiter.limit("5/minute") #5 attempts per minute
def post_login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.execute(text("SELECT * FROM users WHERE username = :username"),{"username": username}).fetchone()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid credentials")
    
    if (username == ADMIN_USERNAME1 and password == ADMIN_PASS1):
        return RedirectResponse(
        url=f"/dashboard?role={user.role}&user_id={user.id}",
        status_code=status.HTTP_302_FOUND
    )
    if user.locked_until and user.locked_until > datetime.now():
        remaining = (user.locked_until - datetime.now()).seconds
        return templates.TemplateResponse("response.html", {
                "request": request,
                "title": "Error!",
                "message": f"Account locked. Try again in {remaining} seconds",
                "return_url": "/"
            })
    if not pwd_context.verify(password, user.password):
        db.execute(text("""UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = :username"""),{"username": username})
        if user.failed_attempts + 1 >= 5: #lock the account after 5 failed attempts
            db.execute(
                text("""UPDATE users SET locked_until = :lock_time WHERE username = :username"""),{ "username": username, "lock_time": datetime.now() + timedelta(minutes=15)})
            db.execute(
                text("""INSERT INTO logs (username, action, ip_address, user_agent) VALUES (:username, :action, :ip_address, :user_agent)"""),
                {
                    "username": username,
                    "action": "Failed login attempt",
                    "ip_address": request.client.host,
                    "user_agent": request.headers.get("user-agent", "unknown")
                }
            )

        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid credentials")

    #reset the count of failed attempts on successful login
    db.execute(text("""UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = :username"""),{"username": username})
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")

    db.execute(
        text("""INSERT INTO logs (username, action, ip_address, user_agent) VALUES (:username, :action, :ip_address, :user_agent)"""),
        {
            "username": username,
            "action": "User logged in",
            "ip_address": ip_address,
            "user_agent": user_agent
        }
    )

    db.commit()
    return RedirectResponse(
        url=f"/dashboard?role={user.role}&user_id={user.id}",
        status_code=status.HTTP_302_FOUND
    )



@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(req: Request, user_id: int, db: Session = Depends(get_db)):
    user = db.execute(text("SELECT * FROM users WHERE id = :user_id"), {"user_id": user_id}).fetchone()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    role = user[3]
    logs, messages, complaints = [], [], []
    accounts = db.execute(text("SELECT * FROM accounts WHERE user_id = :user_id"), {"user_id": user_id}).fetchall()

    if role == "admin":
        logs = db.execute(text("SELECT * FROM logs")).fetchall()
        messages = db.execute(text("SELECT * FROM messages")).fetchall()
        complaints = db.execute(text("SELECT * FROM complaints")).fetchall()

    return templates.TemplateResponse("dashboard.html", {
        "request": req,
        "user_id": user_id,
        "uname": user[1],
        "role": role,
        "avatar_url": user.avatar_url, 
        "logs": logs,
        "messages": messages,
        "complaints": complaints,
        "accounts": accounts
    })




@router.post("/update-profile")
async def update_profile( request: Request, user_id: int = Form(...), avatar_url: str = Form(...), db: Session = Depends(get_db)):
    #SSRF vuln, no validation of user-supplied URL
    try:
        response = requests.get(avatar_url, timeout=5)
        if response.status_code == 200:
            db.execute( text("UPDATE users SET avatar_url = :url WHERE id = :user_id"), {"url": avatar_url, "user_id": user_id})
            db.commit()
            return templates.TemplateResponse("response.html", {
                "request": request,
                "title": "Success!",
                "message": f"Profile picture updated from {avatar_url}",
                "return_url": f"/profile?user_id={user_id}"
            })
    except Exception as e:
        return templates.TemplateResponse("response.html", { "request": request, "title": "Error!", "message": f"Failed to fetch image: {str(e)}", "return_url": f"/profile?user_id={user_id}"})

@router.get("/profile", response_class=HTMLResponse)
def get_profile(req: Request, user_id: int, db: Session = Depends(get_db)):
    user = db.execute(text("SELECT id, username, avatar_url FROM users WHERE id = :user_id"),{"user_id": user_id}).fetchone()
    if not user:
        raise HTTPException( status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
    return templates.TemplateResponse(
        "profile.html",
        {"request": req, "user": user, "user_id": user_id}
    )


@router.get("/view-statement", response_class=HTMLResponse)
def view_statement(req: Request, user_id: int, db: Session = Depends(get_db)):
    transactions = db.execute(text("SELECT * FROM transactions WHERE account_id = :user_id"), {"user_id": user_id}).fetchall()
    
    return templates.TemplateResponse("statement.html", {"request": req, "user_id":user_id, "transactions": transactions})



@router.post("/upload-complaint")
async def upload_complaint(request: Request, user_id: int = Form(...), file: UploadFile = File(...)):
    file_location = f"uploads/{file.filename}"
    os.makedirs(os.path.dirname(file_location), exist_ok=True)

    with open(file_location, "wb") as f:
        f.write(await file.read())
    return templates.TemplateResponse("response.html", {
        "request": request,
        "title": "Succes! File uploaded",
        "message": "File uploaded successfully!",
        "return_url": f"/messaging?user_id={user_id}",
        "filename": file.filename
    })


@router.get("/messaging", response_class=HTMLResponse)
def get_messaging_page(req: Request, user_id: int):
    return templates.TemplateResponse("messages.html", {"request": req, "user_id": user_id})


@router.get("/transfer", response_class=HTMLResponse)
def get_transactions_page(req: Request, user_id: int):
    return templates.TemplateResponse("transfer.html", {"request":req, "user_id":user_id})

@router.post("/transfer")
def transfer_money(sender_id: int = Form(...),receiver_id: int = Form(...),amount: float = Form(...),db: Session = Depends(get_db)):
    sender_account = db.execute(text("SELECT * FROM accounts WHERE user_id = :user_id"), {"user_id": sender_id}).fetchone()
    receiver_account = db.execute(text("SELECT * FROM accounts WHERE user_id = :user_id"), {"user_id": receiver_id}).fetchone()

    if not sender_account or not receiver_account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid account/s")

    if sender_account[2] < amount:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient balance")

    db.execute(text("INSERT INTO transactions (account_id, amount, recipient_id, description) VALUES (:account_id, :amount, :recipient_id, :description)"),
               {"account_id": sender_account[0], "amount": amount, "recipient_id": receiver_id, "description": "Transfer"})
    db.execute(text("UPDATE accounts SET balance = balance - :amount WHERE user_id = :user_id"), {"amount": amount, "user_id": sender_id})
    db.execute(text("UPDATE accounts SET balance = balance + :amount WHERE user_id = :user_id"), {"amount": amount, "user_id": receiver_id})
    db.commit()

    db.execute(text("INSERT INTO logs (action, username) VALUES (:action, :username)"),
               {"action": f"Transferred {amount} from user: {sender_id} to user {receiver_id}", "username": sender_id})
    db.commit()
    
    return {"message": "Transfer successful"}

