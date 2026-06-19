import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load variables
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyber_threats.db")

# SQLite needs connect_args={"check_same_thread": False} to be used in multithreaded FastAPI context
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)
    input_value = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)  # URL, EMAIL, IP, DOMAIN, OSINT
    result = Column(Text, nullable=False)       # JSON stringified analysis response
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    analyst_notes = Column(Text, default="")
    
    # Police-focused fields
    fir_case_id = Column(String, default="")
    investigator_name = Column(String, default="")
    complaint_id = Column(String, default="")

# Create database tables
def init_db():
    Base.metadata.create_all(bind=engine)

# Dependency to get db session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
