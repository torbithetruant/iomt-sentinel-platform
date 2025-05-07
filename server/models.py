from sqlalchemy import Column, Integer, Float, String, DateTime, create_engine, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone

Base = declarative_base()

class SensorRecord(Base):
    __tablename__ = "sensor_data"
    id = Column(Integer, primary_key=True)
    device_id = Column(String)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    heart_rate = Column(Integer)
    spo2 = Column(Float)
    temperature = Column(Float)
    systolic_bp = Column(Integer)                 # mmHg
    diastolic_bp = Column(Integer)                # mmHg
    respiration_rate = Column(Integer)             # respirations/min
    glucose_level = Column(Float)              # mg/dL ou mmol/L
    ecg_summary = Column(String)

class SystemStatus(Base):
    __tablename__ = "system_status"
    id = Column(Integer, primary_key=True)
    device_id = Column(String)
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


DATABASE_URL = "sqlite:///./data.db"
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(bind=engine)

