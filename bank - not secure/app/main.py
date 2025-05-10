from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.routes import router
from app.database import Base, engine, get_db
from sqlalchemy.orm import sessionmaker

app=FastAPI()

@app.on_event("startup")
def on_startup():
    get_db()


app.include_router(router)

app.mount("/static", StaticFiles(directory="static"), name="static")