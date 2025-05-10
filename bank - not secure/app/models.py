from sqlalchemy import Column, Integer, Numeric, String, Float, ForeignKey, Text
from sqlalchemy.orm import relationship, declarative_base

Base=declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)

    accounts = relationship("Account", back_populates="user")
    messages=relationship("Message", back_populates="user")
    complaints=relationship("Complaint", back_populates="user")

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    balance = Column(Float)
    account_type = Column(String(50))
    balance = Column(Numeric(10, 2))

    user = relationship("User", back_populates="accounts")
    transactions = relationship("Transaction", back_populates="account")

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey('accounts.id'))
    amount = Column(Float)
    recipient_id = Column(Integer)#insecure design
    description =Column(String)
    account = relationship("Account", back_populates="transactions")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    content = Column(String) #for injection
    user = relationship("User", back_populates="messages")

class Complaint(Base):
    __tablename__ = "complaints"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    path=Column(String) #storing paths directly
    user = relationship("User", back_populates="complaints")

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String)
    timestamp = Column(String)
    username = Column(String)