import os
import socket
from typing import Optional
from fastapi import APIRouter, Depends, Form, HTTPException, Response, requests, status, File, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session
from fastapi.responses import HTMLResponse
from app.database import get_db
from fastapi import Request
from fastapi.templating import Jinja2Templates
from markupsafe import escape
from fastapi.responses import HTMLResponse
from jinja2 import Environment, select_autoescape
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
import os
import re
import uuid
from passlib.context import CryptContext
from fastapi import Form, Response, Depends, Request
from sqlalchemy.orm import Session
from fastapi.responses import RedirectResponse
from datetime import timedelta
import jwt
from datetime import datetime, timedelta


env = Environment(
    autoescape=select_autoescape(['html', 'xml']),
    enable_async=True
)
router = APIRouter()
templates = Jinja2Templates(directory="app/views")


def log_action(db: Session, request: Request, user_id: int, username: str, action: str, status: str = "SUCCESS", details: str = ""):
    try:
        client_ip = request.client.host if request.client else "0.0.0.0"
        user_agent = request.headers.get("user-agent", "")
        
        db.execute(text("""
            INSERT INTO logs (user_id, action, timestamp, username, status, ip_address, details)
            VALUES (:user_id, :action, NOW(), :username, :status, :ip, :details)
        """), {
            "user_id": user_id,
            "action": f"{action} - {status}",
            "username": username,
            "status": status,
            "ip": client_ip,
            "details": f"{details} | User-Agent: {user_agent}"
        })
        db.commit()
        
    except Exception as e:
        print(f"Failed to log action: {str(e)}")


#                                      JWT TOKEN                                           #

SECRET_KEY = "BANK_KEYYY"
ALGORITHM = "HS256"

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=60)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

from fastapi import Depends, HTTPException, status

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.PyJWTError as e:
        print(f"Error decoding token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")

#                                      HOME                                           #

@router.get("/", response_class=HTMLResponse)
async def read_root(req: Request):
    return templates.TemplateResponse("home.html", {"request": req})

#                                      REGISTER                                           #

@router.get("/register", response_class=HTMLResponse)
def get_register(req: Request):
    return templates.TemplateResponse("register.html", {"request": req})

import bcrypt

@router.post("/register")
def post_register(username: str = Form(...), password: str = Form(...), role: str = Form(...), db: Session = Depends(get_db)):
    existing_user = db.execute(text("SELECT * FROM users WHERE username = :username"), {"username": username}).fetchone()
    if existing_user:
        log_action(db=db, request=None, user_id=None, username=username, action="register", status="FAIL", details="Username already taken")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    db.execute(text("""
        INSERT INTO users (username, password, role, avatar_url) VALUES (:username, :password, :role, :avatar_url) """), {
        "username": username,
        "password": hashed_password,
        "role": role,
        "avatar_url": "https://img.freepik.com/free-vector/businessman-character-avatar-isolated_24877-60111.jpg?t=st=1746652457~exp=1746656057~hmac=e629c4a41bb033c9070818b13a8b98ff0eb9f6ac5070f1f06d536b82b5c1a71b&w=826"}
    )
    db.commit()
    user = db.execute(text("SELECT * FROM users WHERE username = :username"), {"username": username}).fetchone()
    if user:
        user_id = user[0]
        log_action(db=db, request=None, user_id=user_id, username=username, action="register", status="SUCCESS", details="User registered successfully")
    return RedirectResponse(url="/dashboard", status_code=302)



#                                      LOGIN                                           #

@router.get("/login", response_class=HTMLResponse)
def get_login(req: Request):
    return templates.TemplateResponse("login.html", {"request": req})



load_dotenv()

ADMIN_USERNAME1 = os.getenv("ADMIN_USERNAME1", "").strip()
ADMIN_USERNAME2 = os.getenv("ADMIN_USERNAME2", "").strip()
ADMIN_PASS1 = os.getenv("ADMIN_PASS1", "").strip()
ADMIN_PASS2 = os.getenv("ADMIN_PASS2", "").strip()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post("/login", response_class=HTMLResponse)
def login_user(request: Request, response: Response, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    try:
        if (username == ADMIN_USERNAME1 and password == ADMIN_PASS1) or \
           (username == ADMIN_USERNAME2 and password == ADMIN_PASS2):
            user = db.execute(text("SELECT * FROM users WHERE username = :username"),{"username": username}).fetchone()
            user_id = user[0]
            log_action( db=db, request=request, user_id=user_id, username=username, action="admin_login", details="Admin authentication")
            
            access_token = create_access_token(data={"user_id": user_id})
            res = RedirectResponse(url="/dashboard", status_code=302)
            res.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="Lax", max_age=3600)
            return res

        user = db.execute(text("SELECT * FROM users WHERE username = :username"),{"username": username}).fetchone()
        
        if not user:
            log_action(
                db=db,
                request=request,
                user_id=None,
                username=username,
                action="login_attempt",
                status="FAIL",
                details="Invalid username"
            )
            return _error(request, "Invalid username", "/login")

        pwd = user[2]
        if pwd.startswith("$2b$"):
            if pwd_context.verify(password, pwd):
                log_action(db=db, request=request, user_id=user[0], username=username, action="login", details="Successful login")
                access_token = create_access_token(data={"user_id": user[0]})
                res = RedirectResponse(url="/dashboard", status_code=302)
                res.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="Lax", max_age=3600)
                return res
            else:
                log_action( db=db, request=request, user_id=user[0], username=username, action="login_attempt", status="FAIL", details="Incorrect password")
                return _error(request, "Incorrect password", "/login")
        else:
            log_action( db=db, request=request, user_id=user[0], username=username, action="login_attempt", status="FAIL", details="Old password format")
            return _error(request, "Incorrect password", "/login")
            
    except Exception as e:
        log_action( db=db, request=request, user_id=None, username=username, action="login_error", status="FAIL", details=f"System error: {str(e)}" )
        raise


def _error(request: Request, message: str, return_url: str):
    return templates.TemplateResponse("response.html", {
        "request": request,
        "title": "Error! Login Failed",
        "message": message,
        "return_url": return_url
    })


@router.get("/logout")
def logout(request: Request, db:Session=Depends(get_db), user_id: int= Depends(get_current_user)):
    user = db.execute(text("SELECT * FROM users WHERE id = :user_id"), {"user_id": user_id}).fetchone()            
    response=RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key="access_token")
    log_action(
        db=db,
        request=request,
        user_id=user_id,
        username=user[1],
        action="logout", details="User logged out successfully"
    )
    return RedirectResponse(url="/login", status_code=302)

#                                      DASHBOARD                                           #

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(req: Request, user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    # user_id=req.session.get("user_id")
    print(f"user_id: {user_id}")
    if not user_id:
        return RedirectResponse("/login", status_code=302)

    user = db.execute(text("SELECT * FROM users WHERE id = :user_id"), {"user_id": user_id}).fetchone()
    if not user:
        return RedirectResponse("/login", status_code=302)
    role = user[3]
    logs = db.execute(text("SELECT * FROM logs")).fetchall()
    raw_messages = db.execute(text("SELECT * FROM messages")).fetchall()
    complaints = db.execute(text("SELECT * FROM complaints")).fetchall()
    messages = [(msg[0], msg[1], escape(msg[2])) for msg in raw_messages]

    accounts = db.execute(text("SELECT * FROM accounts WHERE user_id = :user_id"), {"user_id": user_id}).fetchall()

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



from urllib.parse import urlparse
import ipaddress

def is_internal_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def validate_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        #to block any non-HTTP/HTTPS URLs
        if parsed.scheme not in ('http', 'https'):
            return False
        #resolve domain to check for internal IPs
        try:
            host_ip = socket.gethostbyname(parsed.hostname)
            if is_internal_ip(host_ip):
                return False
        except socket.gaierror:
            return False
        #to block common metadata endpoints
        blocked_paths = {
            '/latest/meta-data',
            '/metadata',
            '/internal'
        }
        if any(p in parsed.path for p in blocked_paths):
            return False
        allowed_imgs_extensions = {'.jpg', '.jpeg', '.png', '.gif'}
        ext = os.path.splitext(parsed.path)[1].lower()
        return ext in allowed_imgs_extensions
    except Exception:
        return False


import requests
@router.post("/update-profile")
async def update_profile( request: Request, user_id: int = Form(...), avatar_url: str = Form(...), db: Session = Depends(get_db)):
    #SSRF vuln, no validation of user-supplied URL
    user = db.execute(text("SELECT id, username, avatar_url FROM users WHERE id = :user_id"),{"user_id": user_id}).fetchone()
    user_name=user[1]
    if not user:
        log_action( db=db, request=request, user_id=user_id, username=user_name, action="profile_update", status="FAIL", details=f"Invalid avatar URL: {avatar_url}" )
        return templates.TemplateResponse("response.html", { "request": request, "title": "Error!", "message": "Invalid profile picture URL", "return_url": f"/profile"})
    try:
        #to restrict redirects
        response = requests.get(avatar_url, timeout=5, allow_redirects=False, headers={'User-Agent': 'MyApp Avatar Fetcher'})
        #verify the content's type
        content_type=response.headers.get('Content-Type', '')
        if not content_type.startswith('image/'):
            log_action( db=db, request=request, user_id=user_id, username=user_name, action="profile_update", status="FAIL", details=f"Invalid content type: {content_type}" )
            return templates.TemplateResponse("response.html", {
            "request": request,
            "title": "Error!",
            "message": "URL doesn't return an image!",
            "return_url": f"/profile"
        })

        if response.status_code == 200:
            db.execute( text("UPDATE users SET avatar_url = :url WHERE id = :user_id"), {"url": avatar_url, "user_id": user_id})
            db.commit()
            return templates.TemplateResponse("response.html", {
                "request": request,
                "title": "Success!",
                "message": f"Profile picture updated from {avatar_url}",
                "return_url": f"/profile"
            })
    except Exception as e:
        log_action( db=db, request=request, user_id=user_id, username=user_name, action="profile_update_error", status="FAIL", details=f"Error: {str(e)}" )
        return templates.TemplateResponse("response.html", { "request": request, "title": "Error!", "message": f"Failed to fetch image: {str(e)}", "return_url": f"/profile?user_id={user_id}"})

@router.get("/profile", response_class=HTMLResponse)
def get_profile(req: Request, user_id: int= Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.execute(text("SELECT id, username, avatar_url FROM users WHERE id = :user_id"),{"user_id": user_id}).fetchone()
    if not user:
        raise HTTPException( status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
    return templates.TemplateResponse(
        "profile.html",
        {"request": req, "user": user, "user_id": user_id}
    )


#                                      Statement                                           #

@router.get("/view-statement", response_class=HTMLResponse)
def view_statement(req: Request, user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    transactions = db.execute(text("SELECT * FROM transactions WHERE account_id = :user_id"), {"user_id": user_id}).fetchall()
    
    return templates.TemplateResponse("statement.html", {"request": req, "user_id":user_id, "transactions": transactions})

#                                      Complaint                                           #

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf"}

def is_allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS

import magic


DANGEROUS_EXTENSIONS = {".php", ".exe", ".bat", ".sh", ".js", ".asp", ".php3", ".cgi", ".pl"}
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf", ".gif", ".txt"}
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "application/pdf", "image/gif", "text/plain"}

#to check the file extension
def is_allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS and ext not in DANGEROUS_EXTENSIONS

#to check the MIME type of the file
def is_allowed_file_type(file: UploadFile) -> bool:
    file_content = file.file.read(2048)  #reads the first few bytes of the file
    file.file.seek(0)#resets the file pointer to the beginning of the file
    mime_type = magic.from_buffer(file_content, mime=True)
    return mime_type in ALLOWED_MIME_TYPES

def validate_filename(filename: str) -> str:
    filename = os.path.basename(filename)
    filename = re.sub(r'[^a-zA-Z0-9\_.-]', '_', filename) #replaces unsafe characters
    return filename

@router.post("/upload-complaint", response_class=HTMLResponse)
async def upload_complaint(req: Request, user_id: int =  Depends(get_current_user), file: UploadFile = File(...)):

    if not is_allowed_file(file.filename) or not is_allowed_file_type(file):
        return templates.TemplateResponse("response.html", {
            "request": req,
            "title": "Upload Error",
            "message": "File type is not allowed!",
            "return_url": f"/dashboard"
        })
    original_filename = validate_filename(file.filename)
    ext = os.path.splitext(original_filename)[1]
    log_action(db=req.state.db, request=req, user_id=user_id, username="unknown", action="upload_complaint", status="FAIL", details="Invalid file type")

    safe_filename = f"{uuid.uuid4()}{ext}"

    file_location = f"/secure_uploads/{safe_filename}"
    os.makedirs(os.path.dirname(file_location), exist_ok=True)
    with open(file_location, "wb") as f:
        f.write(await file.read())

    log_action(db=req.state.db, request=req, user_id=user_id, username="unknown", action="upload_complaint", status="SUCCESS", details=f"Complaint uploaded: {safe_filename}")

    return templates.TemplateResponse("response.html", {
        "request": req,
        "title": "Upload Successful",
        "message": f"File '{original_filename}' uploaded successfully!",
        "return_url": f"/dashboard"
    })
#                                      Messages                                           #

import re

def valid_message(content: str) -> str:
    if not content:
        return ""
    content = re.sub(r'<(script|iframe|object|embed|form|link|style|svg|meta)[^>]*>.*?</\1>', '', content, flags=re.IGNORECASE)
    content = re.sub(r'on\w+="[^"]*"', '', content, flags=re.IGNORECASE)    
    return escape(content.strip())

@router.post("/send-message", response_class=HTMLResponse)
def send_message( req: Request, user_id: int = Depends(get_current_user), content: str = Form(...), db: Session = Depends(get_db)):
    max_length = 1000
    if len(content) > max_length:
        return templates.TemplateResponse("response.html", {
            "request": req,
            "title": "Error! Message Too Long",
            "message": f"Your message is too long! Please limit it to {max_length} characters.",
            "return_url": f"/messaging"
        })

    sanitized_content = valid_message(content)

    if not sanitized_content:
        return templates.TemplateResponse("response.html", {
            "request": req,
            "title": "Message Error",
            "message": "Message cannot be empty or contains invalid content!",
            "return_url": f"/messaging"
        })

    db.execute(text("INSERT INTO messages (user_id, content) VALUES (:user_id, :content)"), {"user_id": user_id, "content": sanitized_content})
    db.commit()

    return templates.TemplateResponse("response.html", {
        "request": req,
        "title": "Message Sent",
        "message": "Your message has been sent successfully.",
        "return_url": f"/messaging"
    })

@router.get("/messaging", response_class=HTMLResponse)
def get_messaging_page(req: Request, user_id: int = Depends(get_current_user)):
    return templates.TemplateResponse("messages.html", {"request": req, "user_id": user_id})


#                                      TRANSFER                                           #

@router.get("/transfer", response_class=HTMLResponse)
def get_transactions_page(req: Request, user_id: int = Depends(get_current_user)):
    return templates.TemplateResponse("transfer.html", {"request":req, "user_id":user_id})


@router.post("/transfer", response_class=HTMLResponse)
def transfer_money(req: Request, user_id: int = Depends(get_current_user), receiver_id: int = Form(...), amount: float = Form(...), db: Session = Depends(get_db)):
    sender_id=user_id
    if not sender_id:
        return templates.TemplateResponse("response.html", {
            "request": req,
            "title": "Transfer Error",
            "message": "You must be logged in to transfer money.",
            "return_url": "/login"
        })
    if amount <= 0:
        return templates.TemplateResponse("response.html", {
            "request": req,
            "title": "Transfer Error",
            "message": "Transfer amount must be a positive value.",
            "return_url": f"/transfer?user_id={sender_id}"
        })

    sender_account = db.execute(text("SELECT * FROM accounts WHERE user_id = :user_id"), {"user_id": sender_id}).fetchone()
    receiver_account = db.execute(text("SELECT * FROM accounts WHERE user_id = :user_id"), {"user_id": receiver_id}).fetchone()

    if not sender_account or not receiver_account:
        return templates.TemplateResponse("response.html", {
            "request": req,
            "title": "Transfer Error",
            "message": "Invalid sender or receiver account.",
            "return_url": f"/transfer?user_id={sender_id}"
        })

    if sender_account[2] < amount:
        return templates.TemplateResponse("response.html", {
            "request": req,
            "title": "Transfer Error",
            "message": "Insufficient balance.",
            "return_url": f"/transfer?user_id={sender_id}"
        })
    db.execute(text("INSERT INTO transactions (account_id, amount, recipient_id, description) VALUES (:account_id, :amount, :recipient_id, :description)"),
               {"account_id": sender_account[0], "amount": amount, "recipient_id": receiver_id, "description": "Transfer"})
    db.execute(text("UPDATE accounts SET balance = balance - :amount WHERE user_id = :user_id"), {"amount": amount, "user_id": sender_id})
    db.execute(text("UPDATE accounts SET balance = balance + :amount WHERE user_id = :user_id"), {"amount": amount, "user_id": receiver_id})
    db.commit()

    db.execute(text("INSERT INTO logs (action, username) VALUES (:action, :username)"),
               {"action": f"Transferred {amount} from user: {sender_id} to user {receiver_id}", "username": str(sender_id)})
    db.commit()

    return templates.TemplateResponse("response.html", {
        "request": req,
        "title": "Transfer Success",
        "message": f"Transferred ${amount} to user {receiver_id}.",
        "return_url": f"/dashboard?user_id={sender_id}"
    })
