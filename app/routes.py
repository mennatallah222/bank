import os
from fastapi import APIRouter, Depends, Form, HTTPException, status
from markupsafe import Markup
from sqlalchemy import text
from sqlalchemy.orm import Session
from fastapi.responses import HTMLResponse
from app.database import get_db
from fastapi import Request
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/views")


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
    db.execute(text("INSERT INTO users (username, password, role) VALUES (:username, :password, :role)"), {"username": username, "password": password, "role": role})
    db.commit()
    user = db.execute(text("SELECT * FROM users WHERE username = :username AND password = :password"), {"username": username, "password": password}).fetchone()
    
    if user:
        user_id=user[0]
    response = RedirectResponse(url=f"/dashboard?user_id={user_id}", status_code=status.HTTP_302_FOUND)
    return response

@router.get("/login", response_class=HTMLResponse)
def get_login(req: Request):
    return templates.TemplateResponse("login.html", {"request": req})

@router.post("/login")
def post_login( username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.execute(text(f"SELECT * FROM users WHERE username = '{username}' ")).fetchone()

    if user:
        user_id=user[0]
        username = user[1]
        db.execute(text("INSERT INTO logs (action, username) VALUES (:action, :username)"), {"action": f"User: {username} logged in", "username": username})
        db.commit()

        response = RedirectResponse(url=f"/dashboard?role={user.role}&user_id={user_id}", status_code=status.HTTP_302_FOUND)
        return response

    return templates.TemplateResponse("response.html", {
            "title": "Error! Login Failed",
            "message": "Invalid credintials",
            "return_url": "/login"
        })

from fastapi.responses import RedirectResponse


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
        "logs": logs,
        "messages": messages,
        "complaints": complaints,
        "accounts": accounts
    })


@router.get("/view-statement", response_class=HTMLResponse)
def view_statement(req: Request, user_id: int, db: Session = Depends(get_db)):
    transactions = db.execute(text("SELECT * FROM transactions WHERE account_id = :user_id"), {"user_id": user_id}).fetchall()
    
    return templates.TemplateResponse("statement.html", {"request": req, "user_id":user_id, "transactions": transactions})


from fastapi import File, UploadFile

@router.post("/upload-complaint")
async def upload_complaint(file: UploadFile = File(...)):
    file_location = f"uploads/{file.filename}"
    os.makedirs(os.path.dirname(file_location), exist_ok=True)

    with open(file_location, "wb") as f:
        f.write(await file.read())
    return {"message": "File uploaded successfully!", "filename": file.filename}

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(req: Request, user_id: int, db: Session = Depends(get_db)):
    user = db.execute(text("SELECT * FROM users WHERE id = :user_id"), {"user_id": user_id}).fetchone()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    role = user[3]
    logs, raw_messages, complaints = [], [], []
    accounts = db.execute(text("SELECT * FROM accounts WHERE user_id = :user_id"), {"user_id": user_id}).fetchall()

    if role == "admin":
        logs = db.execute(text("SELECT * FROM logs")).fetchall()
        raw_messages = db.execute(text("SELECT * FROM messages")).fetchall()
        complaints = db.execute(text("SELECT * FROM complaints")).fetchall()
        messages = [
            (msg[0], msg[1], Markup(msg[2]))
            for msg in raw_messages
        ]
    else:
        messages = []

    return templates.TemplateResponse("dashboard.html", {
        "request": req,
        "user_id": user_id,
        "uname": user[1],
        "role": role,
        "logs": logs,
        "messages": messages,
        "complaints": complaints,
        "accounts": accounts
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

