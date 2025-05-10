from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.routes import router
from app.database import Base, engine, get_db
from sqlalchemy.orm import sessionmaker
from starlette.middleware.sessions import SessionMiddleware

app=FastAPI()
app.add_middleware(SessionMiddleware, secret_key="banks-secret")


@app.on_event("startup")
def on_startup():
    get_db()


app.include_router(router)

app.mount("/static", StaticFiles(directory="static"), name="static")