from sqlalchemy import Column, Integer, Float, String, DateTime, create_engine, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone

Base = declarative_base()

# Define the database models
# These models represent the structure of the database tables
# and are used to interact with the database using SQLAlchemy ORM.
# The models are defined using SQLAlchemy's declarative base


class SensorRecord(Base):
    __tablename__ = "sensor_data"
    id = Column(Integer, primary_key=True)
    device_id = Column(String)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    heart_rate = Column(Integer)
    spo2 = Column(Float)
    temperature = Column(Float)
    systolic_bp = Column(Integer)                 
    diastolic_bp = Column(Integer)                
    respiration_rate = Column(Integer)             
    glucose_level = Column(Float)              
    ecg_summary = Column(String)
    label = Column(Integer, default=0)                      

class SystemStatus(Base):
    __tablename__ = "system_status"
    id = Column(Integer, primary_key=True)
    device_id = Column(String)
    username = Column(String)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    sensor_type = Column(String)                  
    ip_address = Column(String)                   
    firmware_version = Column(String)                
    status = Column(Integer)                        
    data_frequency_seconds = Column(Integer)       
    checksum_valid = Column(Boolean)
    os_version = Column(String)
    update_required = Column(Boolean)
    disk_free_percent = Column(Float)

class SystemRequest(Base):
    __tablename__ = "system_request"
    id = Column(Integer, primary_key=True)
    device_id = Column(String)
    requested_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    fulfilled = Column(Boolean, default=False)

class UserAccount(Base):
    __tablename__ = "user_account"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    role = Column(String)

class Device(Base):
    __tablename__ = "device"
    id = Column(Integer, primary_key=True)
    device_id = Column(String, unique=True)
    username = Column(String, unique=True)

DATABASE_URL = "sqlite:///./data.db"
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(bind=engine)

