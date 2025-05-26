# === Standard Library ===
import os
import time
import json
import asyncio
import requests
import httpx
from datetime import datetime, timezone, timedelta
from typing import Optional

# === Third-Party Libraries ===

## FastAPI & Starlette
from fastapi import FastAPI, Depends, Request, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

## Pydantic
from pydantic import BaseModel

## SQLAlchemy (Async)
from sqlalchemy import select, delete, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

## Authentication & Security
from jose import jwt, JWTError

## Rate Limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

## Prometheus Monitoring
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

# === Internal Modules ===

## Auth
from auth import require_role, get_jwt_username

## Database Models
from database.models import AsyncSessionLocal, SensorRecord, SystemStatus, SystemRequest, Device, DeviceTrust

## Logging
from logs.scripts.log import logger
from logs.scripts.ip_context import is_private_ip, get_ip_location
from logs.scripts.log_rate_tracker import get_user_action_and_rate

# Optional future import (commented out)
# from keycloak_file_monitor import monitor_keycloak_log

from security.incident_handler import incident_responder, monitor_logs_with_llm
import security.anomaly_state



# Change with your Keycloak public key
KEYCLOAK_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA69YwDPnk80OzGdp2doWI+2S0XYrmF4kkekFounifw+2h6lTNqEsGSwT8NCaAI3N/rcHxTQb17QAL3xrRdXdQiBGJmJypsl3wn+ryZCElG9i3mnRsr5R6GgNiqkf4jDDaA5leQ1wQPOl12hJTjj58X3g9ZmPVbV7PH16pCOYwhRJgs2mnCm0UajtNr4Kwzq5KhLlItE1oeQ6DvXfTEL7aEeLqW+Mx1BuQ3NPn9l9nXHs6ii3PLKyXBxcTsIEdCVKiADDRBxSsRxSPwKxgS6AflTSDwN+/Up7wS//UUqEb03xm0xiWuIF6T3tloyssx71JXijHOPG/q2KdhnqNBcy7TQIDAQAB-----END PUBLIC KEY-----
"""

ALGORITHM = "RS256"
ISSUER = "http://localhost:8080/realms/iot_realm"

post = ["patient", "doctor"]

KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
CLIENT_ID = "iot_backend"

# Change with your Keycloak client secret
CLIENT_SECRET = "q1nMXKR6EKwafhEcDkeugyvgmbhGpbSp"

LOG_PATH = "logs/server.log"


#############################
# LOGGING
#############################

class AccessLogMiddleware(BaseHTTPMiddleware):
    EXCLUDED_PATHS = ["/favicon.ico", "/static", "/health", "/robots.txt", "/metrics", "/redirect"]

    async def dispatch(self, request: StarletteRequest, call_next):
        path = request.url.path
        if any(path.startswith(excl) for excl in self.EXCLUDED_PATHS):
            return await call_next(request)

        start_time = time.time()
        ip = request.headers.get("X-Forwarded-For") or request.client.host
        method = request.method
        user_agent = request.headers.get("user-agent", "-")
        auth_header = request.headers.get("authorization")
        token = request.cookies.get("access_token")

        location = get_ip_location(ip) if not is_private_ip(ip) else "Private IP"
        username = "-"
        device_id = "-"
        alert = 0

        if not token and auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1]

        if token:
            try:
                payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
                username = payload.get("preferred_username", "-")
            except JWTError:
                logger.warning(f"{ip} {location} - {username} {device_id} \"{method} {path}\" [Invalid Token] {user_agent}")

        if method in ("POST", "PUT") and not path.startswith("/login"):
            try:
                body = await request.body()
                request._body = body
                json_data = json.loads(body)
                device_id = json_data.get("device_id", "-")
                alert = json_data.get("label", 0)
            except:
                logger.warning(f"{ip} {location} - {username} {device_id} \"{method} {path}\" [Invalid JSON] {user_agent}")

        response = await call_next(request)
        duration = round((time.time() - start_time) * 1000)
        action, rate = get_user_action_and_rate(username, path)

        # Prépare le préfixe commun du log
        log_prefix = f'[Action : {action}] {ip} ({location}) - {username} {device_id} "{method} {path}" {response.status_code} [Request rate: {rate}/min]'

        # Gestion des logs en fonction du chemin
        if path.startswith("/login") and method == "POST":
            if response.status_code == 302:
                logger.info(f"{log_prefix} [Login Success] {user_agent}")
            else:
                logger.warning(f"{log_prefix} [Login Failed] {user_agent}")

        elif path.startswith("/api/sensor") or path.startswith("/api/system-status"):
            async with AsyncSessionLocal() as session:
                stmt = select(Device).filter(Device.device_id == device_id, Device.username == username)
                result = await session.execute(stmt)
                device_match = result.scalar_one_or_none()

                context = "[Normal Device]" if device_match else "[New Device Used]"
                label = "[Alert]" if alert == 1 else "[Safe]"
                log_message = f"{log_prefix} {context} {label} {user_agent}"

                if alert == 1:
                    logger.warning(log_message)
                else:
                    logger.info(log_message)

        elif path.startswith("/dashboard"):
            status = "[Dashboard Access]" if response.status_code == 200 else "[Dashboard Access Failed]"
            logger.info(f"{log_prefix} {status} {user_agent}") if response.status_code == 200 else \
                logger.warning(f"{log_prefix} {status} {user_agent}")

        else:
            logger.info(f"{log_prefix} {user_agent} {duration}ms")

        return response

##############################
# APP INITIALIZATION
##############################

# Use of slowapi for rate limiting per user
limiter = Limiter(key_func=get_jwt_username)

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(AccessLogMiddleware)
templates = Jinja2Templates(directory="templates")

# Model for sensor data
class SensorData(BaseModel):
    device_id: str
    timestamp: datetime = datetime.now(timezone.utc)
    heart_rate: Optional[int] = None                   # BPM
    spo2: Optional[float] = None                       # Saturation O2
    temperature: Optional[float] = None                # °C
    systolic_bp: Optional[int] = None                  # mmHg
    diastolic_bp: Optional[int] = None                 # mmHg
    respiration_rate: Optional[int] = None             # respirations/min
    glucose_level: Optional[float] = None              # mg/dL ou mmol/L
    ecg_summary: Optional[str] = None
    label: Optional[int] = None                        # 0: normal, 1: anomalie

# Model for system status data
class SystemStatusData(BaseModel):
    device_id: str
    username: str
    timestamp: datetime = datetime.now(timezone.utc)
    sensor_type: str                   # Ex: cardio, température, etc.
    ip_address: str
    firmware_version: str
    status: int                        # actif / inactif / erreur
    data_frequency_seconds: int       # fréquence d’envoi
    checksum_valid: bool
    os_version: str
    update_required: bool
    disk_free_percent: float

# Model for User account data
class UserAccountData(BaseModel):
    username: str
    email: str
    role: str

class TrustUpdateRequest(BaseModel):
    device_id: str
    num_anomalies_last_hour: int = 0
    failed_auth_ratio: float = 0.0       # between 0 and 1
    ip_drift_score: float = 0.0          # between 0 and 1
    endpoint_unusual: bool = False
    system_alert: bool = False           # ex: checksum error or disk alert

async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session

# Return the list of known devices
async def get_known_devices(db: AsyncSession):
    sensor_result = await db.execute(select(SensorRecord.device_id).distinct())
    system_result = await db.execute(select(SystemStatus.device_id).distinct())

    devices_from_sensors = [row[0] for row in sensor_result.all()]
    devices_from_system = [row[0] for row in system_result.all()]
    all_devices = set(devices_from_sensors + devices_from_system)
    return list(all_devices)

def calculate_trust_score(data: TrustUpdateRequest) -> float:
    score = 1.0
    score -= 0.3 * data.num_anomalies_last_hour
    score -= 0.2 * data.failed_auth_ratio
    score -= 0.2 * data.ip_drift_score
    score -= 0.1 if data.endpoint_unusual else 0.0
    score -= 0.1 if data.system_alert else 0.0
    return max(0.0, min(1.0, score))  # Clamp to [0,1]

###############################
# INDEX PAGE
###############################

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        username = payload.get("preferred_username", "Utilisateur")
    except:
        logger.warning(f"[{request.client.host}], [{request.headers.get('user-agent')}], [GET], [/], [Invalid Token]")
        return RedirectResponse(url="/login")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "roles": roles,
        "username": username
    })

##############################
# API Endpoints
##############################

# Receive sensor data
@app.post("/api/sensor")
@limiter.limit("10/minute")
async def receive_sensor_data(request: Request, data: SensorData, user=Depends(require_role("patient")), db: AsyncSession = Depends(get_db)):

    record = SensorRecord(
        device_id=data.device_id,
        timestamp=data.timestamp,
        heart_rate=data.heart_rate,
        spo2=data.spo2,
        temperature=data.temperature,
        systolic_bp=data.systolic_bp,
        diastolic_bp=data.diastolic_bp,
        respiration_rate=data.respiration_rate,
        glucose_level=data.glucose_level,
        ecg_summary=data.ecg_summary,
        label=data.label
    )
    db.add(record)
    try:
        db.add(record)
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Database error")

    return {"status": "ok"}

# Receive system status data
@app.post("/api/system-status")
@limiter.limit("10/minute")
async def post_system_status(
    request: Request,
    data: SystemStatusData,
    user=Depends(require_role("patient")),
    db: AsyncSession = Depends(get_db)
):
    try:
        # Vérifie si le device existe déjà (requête async)
        result = await db.execute(
            select(Device).where(Device.username == data.username)
        )
        existing_device = result.scalar_one_or_none()

        if not existing_device:
            new_device = Device(device_id=data.device_id, username=data.username)
            db.add(new_device)
            await db.flush()  # Nécessaire si la FK est utilisée juste après

        # Crée une entrée SystemStatus
        entry = SystemStatus(
            device_id=data.device_id,
            username=data.username,
            timestamp=data.timestamp,
            sensor_type=data.sensor_type,
            ip_address=data.ip_address,
            firmware_version=data.firmware_version,
            status=data.status,
            data_frequency_seconds=data.data_frequency_seconds,
            checksum_valid=data.checksum_valid,
            os_version=data.os_version,
            update_required=data.update_required,
            disk_free_percent=data.disk_free_percent
        )
        db.add(entry)
        await db.commit()

    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Error inserting data. Device ID or username may already exist.")
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error")
    
    return {"status": "ok"}

# Receive system request for status system of device
@app.post("/api/system-request")
@limiter.limit("10/minute")
async def request_system_check(
    request: Request,
    device_id: str,
    user=Depends(require_role("it_admin")),
    db: AsyncSession = Depends(get_db)
):
    req = SystemRequest(device_id=device_id)
    db.add(req)
    await db.commit()
    return {"status": f"Demande d’état système envoyée à {device_id}"}

# Check if there is a system request for the device
@app.get("/api/system-request")
@limiter.limit("10/minute")
async def check_for_request(
    request: Request,
    device_id: str,
    user=Depends(require_role("patient")),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(SystemRequest)
        .where(SystemRequest.device_id == device_id, SystemRequest.fulfilled == False)
        .order_by(SystemRequest.requested_at.desc())
    )
    req = result.scalars().first()

    if req:
        logger.debug(f"System request : [{device_id}], [GET], [/api/system-request], [FOUND]")
        return {"request": True}

    logger.debug(f"System request : [{device_id}], [GET], [/api/system-request], [NONE]")
    return {"request": False}

##############################
# SCORING
##############################

# Trust Score Update Background Task
async def loop_trust_scores():
    while True:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Device.device_id))
            device_ids = [row[0] for row in result.all()]

            for device_id in device_ids:
                username = security.anomaly_state.get_user_from_device(device_id)
                metrics = security.anomaly_state.get_full_anomaly_metrics(device_id, username, "")

                features = TrustUpdateRequest(
                    device_id=device_id,
                    num_anomalies_last_hour=metrics["num_anomalies_last_hour"],
                    failed_auth_ratio=metrics["failed_auth_ratio"],
                    ip_drift_score=metrics["ip_drift_score"],
                    endpoint_unusual=metrics["endpoint_unusual"],
                    system_alert=metrics["system_alert"]
                )
                new_score = calculate_trust_score(features)

                existing = await db.execute(select(DeviceTrust).where(DeviceTrust.device_id == device_id))
                row = existing.scalar_one_or_none()

                if not row:
                    db.add(DeviceTrust(device_id=device_id, trust_score=new_score, updated_at=datetime.now(timezone.utc)))
                    print(f"🆕 Added new trust score for {device_id}: {new_score}")
                elif abs(row.trust_score - new_score) >= 0.01:
                    await db.execute(update(DeviceTrust).where(DeviceTrust.device_id == device_id).values(
                        trust_score=new_score,
                        updated_at=datetime.now(timezone.utc)
                    ))
                    print(f"🔄 Updated trust score for {device_id}: {new_score}")
                else:
                    print(f"✅ No update needed for {device_id}: {new_score}")

            await db.commit()
        await asyncio.sleep(60)



# Trust Score Dashboard
@app.get("/dashboard/trust", response_class=HTMLResponse)
async def trust_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "it_admin" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Vous n'avez pas les droits requis."})
    
    result = await db.execute(select(DeviceTrust).order_by(DeviceTrust.trust_score.asc()))
    trust_records = result.scalars().all()

    return templates.TemplateResponse("trust_dashboard.html", {
        "request": request,
        "trust_records": trust_records
    })

##############################
# AUTHENTICATION
##############################

# Login page
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Connect to Keycloak and redirect to the dashboard
@app.post("/login")
@limiter.limit("5/minute")
async def login_and_redirect(request: Request, username: str = Form(...), password: str = Form(...)):
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": username,
        "password": password
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    async with httpx.AsyncClient(verify="certs/cert.pem") as client:
        r = await client.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers)

    if r.status_code != 200:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Failed to authenticate. Please check your credentials."
        })

    token = r.json()["access_token"]
    response = RedirectResponse(url="/redirect", status_code=302)
    response.set_cookie(key="access_token", value=token, httponly=True, secure=True)
    return response

# Middleware to check the token and redirect if necessary
@app.get("/redirect")
def redirect_by_role(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")
    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
    except:
        logger.warning(f"[{request.client.host}], [{request.headers.get('user-agent')}], [GET], [/redirect], [Invalid Token]")
        return RedirectResponse(url="/login")

    return RedirectResponse(url="/")

# Logout and delete the token
@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie("access_token")
    return response

##################################
# EVENT ON STARTUP
##################################

# Clean db requests and send system check requests
async def loop_requests():
    while True:
        async with AsyncSessionLocal() as db:
            now = datetime.now(timezone.utc)

            cutoff = now - timedelta(minutes=10)
            stmt1 = delete(SystemRequest).where(
                SystemRequest.fulfilled == True,
                SystemRequest.requested_at < cutoff
            )
            result1 = await db.execute(stmt1)
            if result1.rowcount > 0:
                logger.info(f"{result1.rowcount} fulfilled system requests cleaned up.")

            cutoff_sys = now - timedelta(days=30)
            stmt2 = delete(SystemStatus).where(SystemStatus.timestamp < cutoff_sys)
            result2 = await db.execute(stmt2)
            if result2.rowcount > 0:
                logger.info(f"{result2.rowcount} old system status entries deleted (>30d).")

            for device_id in await get_known_devices(db):
                logger.debug(f"System check request sent to {device_id}")
                db.add(SystemRequest(device_id=device_id))

            await db.commit()

        await asyncio.sleep(120)


# Actions to perform at startup
@app.on_event("startup")
async def startup_all_tasks():
    asyncio.create_task(loop_requests())
    asyncio.create_task(loop_trust_scores())
    asyncio.create_task(monitor_logs_with_llm(log_path=LOG_PATH, chunk_size=10, delay=1))
    asyncio.create_task(incident_responder())


#################################################
# DASHBOARD
#################################################

# Doctor dashboard
@app.get("/dashboard/doctor", response_class=HTMLResponse)
async def dashboard_doctor(request: Request, device_id: str = None, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "doctor" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Vous n'avez pas les droits requis."})

    result = await db.execute(select(SensorRecord.device_id).distinct())
    device_ids = [row[0] for row in result.all()]
    selected_device = device_id or (device_ids[0] if device_ids else None)

    result = await db.execute(
        select(SensorRecord).where(SensorRecord.device_id == selected_device)
        .order_by(SensorRecord.timestamp.desc()).limit(50)
    )
    records = result.scalars().all()

    timestamps = [r.timestamp.strftime("%H:%M:%S") for r in reversed(records)]
    return templates.TemplateResponse("dashboard_doctor.html", {
        "request": request,
        "timestamps": timestamps,
        "heart_rates": [r.heart_rate for r in reversed(records)],
        "spo2_values": [r.spo2 for r in reversed(records)],
        "temp_values": [r.temperature for r in reversed(records)],
        "systolic_bp": [r.systolic_bp for r in reversed(records)],
        "diastolic_bp": [r.diastolic_bp for r in reversed(records)],
        "respiration_rate": [r.respiration_rate for r in reversed(records)],
        "glucose_level": [r.glucose_level for r in reversed(records)],
        "ecg_summary": [r.ecg_summary for r in reversed(records)],
        "labels": [r.label for r in reversed(records)],
        "device_ids": device_ids,
        "selected_device": selected_device
    })

# Doctor dashboard list
@app.get("/dashboard/doctor/list", response_class=HTMLResponse)
async def dashboard_doctor_list(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        if "doctor" not in payload.get("realm_access", {}).get("roles", []):
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Access denied to the list of patients."})

    result = await db.execute(select(SensorRecord).order_by(SensorRecord.timestamp.desc()).limit(100))
    records = result.scalars().all()

    return templates.TemplateResponse("doctor_list.html", {"request": request, "records": records})

# Doctor dashboard alerts
@app.get("/dashboard/doctor/alerts", response_class=HTMLResponse)
async def doctor_alerts_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        if "doctor" not in payload.get("realm_access", {}).get("roles", []):
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Access denied to the alerts."})

    result = await db.execute(select(SensorRecord).where(SensorRecord.label == 1).order_by(SensorRecord.timestamp.desc()).limit(50))
    alerts = result.scalars().all()

    return templates.TemplateResponse("doctor_alerts.html", {"request": request, "alerts": alerts})

# IT Admin dashboard
@app.get("/dashboard/system", response_class=HTMLResponse)
async def dashboard_system(request: Request, device_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "it_admin" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Access denied to the system dashboard."})

    result = await db.execute(select(SystemStatus.device_id).distinct())
    device_ids = [r[0] for r in result.all()]
    selected_device = device_id or (device_ids[0] if device_ids else None)

    records = []
    if selected_device:
        result = await db.execute(select(SystemStatus).filter_by(device_id=selected_device).order_by(SystemStatus.timestamp.desc()).limit(50))
        records = result.scalars().all()

    timestamps = [r.timestamp.strftime("%H:%M:%S") for r in reversed(records)]
    disk_free = [r.disk_free_percent for r in reversed(records)]
    checksum_valid = [1 if r.checksum_valid else 0 for r in reversed(records)]
    update_required = [1 if r.update_required else 0 for r in reversed(records)]
    sensor_type = [r.sensor_type for r in reversed(records)]
    ip_address = [r.ip_address for r in reversed(records)]
    firmware_version = [r.firmware_version for r in reversed(records)]
    status = [r.status for r in reversed(records)]
    data_frequency = [r.data_frequency_seconds for r in reversed(records)]
    os_versions = [r.os_version for r in reversed(records)]

    return templates.TemplateResponse("system_dashboard.html", {
        "request": request,
        "timestamps": timestamps,
        "disk_free": disk_free,
        "checksum_valid": checksum_valid,
        "update_required": update_required,
        "sensor_type": sensor_type,
        "ip_address": ip_address,
        "firmware_version": firmware_version,
        "status": status,
        "data_frequency": data_frequency,
        "os_versions": os_versions,
        "device_ids": device_ids,
        "selected_device": selected_device
    })

# IT Admin dashboard list
@app.get("/dashboard/system/list", response_class=HTMLResponse)
async def dashboard_system_list(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        if "it_admin" not in payload.get("realm_access", {}).get("roles", []):
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Access denied to the list of system status."})

    result = await db.execute(select(SystemStatus).order_by(SystemStatus.timestamp.desc()).limit(100))
    records = result.scalars().all()

    return templates.TemplateResponse("system_list.html", {"request": request, "records": records})

# IT Admin dashboard alerts
@app.get("/dashboard/system/alerts", response_class=HTMLResponse)
async def system_alerts_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "it_admin" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Access denied to the system alerts."})

    stmt = select(SystemStatus).where(
        (SystemStatus.disk_free_percent < 10) |
        (SystemStatus.update_required == True) |
        (SystemStatus.checksum_valid == False) |
        (SystemStatus.status != 1)
    ).order_by(SystemStatus.timestamp.desc()).limit(50)

    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return templates.TemplateResponse("system_alerts.html", {"request": request, "alerts": alerts})

# IT Admin dashboard logs
@app.get("/dashboard/logs", response_class=HTMLResponse)
async def view_logs(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "it_admin" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Access denied to the logs."})

    if not os.path.exists(LOG_PATH):
        return templates.TemplateResponse("error.html", {"request": request, "message": "Log file not found."})

    with open(LOG_PATH, "r") as f:
        log_content = f.read()[-5000:]

    return templates.TemplateResponse("logs.html", {"request": request, "logs": log_content})

#######################################
# Monitoring
#######################################

# Health check endpoint
@app.get("/health", response_class=PlainTextResponse)
def health_check():
    return "OK"

# Prometheus metrics
active_devices = Gauge("active_iomt_devices", "Nombre de capteurs uniques ayant envoyé des données")
records_total = Gauge("sensor_records_total", "Nombre total de mesures de capteurs")
system_entries = Gauge("system_status_total", "Nombre total de rapports système")
health_alerts_gauge = Gauge("health_alerts_total", "Nombre d'alertes santé")
system_alerts_gauge = Gauge("system_alerts_total", "Nombre d'alertes système")

# Prometheus metrics endpoint
@app.get("/metrics")
async def metrics(db: AsyncSession = Depends(get_db)):
    try:
        # Nombre de capteurs uniques
        result = await db.execute(select(func.count(func.distinct(SensorRecord.device_id))))
        active = result.scalar()
        active_devices.set(active)

        # Nombre total de mesures capteurs
        result = await db.execute(select(func.count()).select_from(SensorRecord))
        total_sensor = result.scalar()
        records_total.set(total_sensor)

        # Nombre total de rapports système
        result = await db.execute(select(func.count()).select_from(SystemStatus))
        total_system = result.scalar()
        system_entries.set(total_system)

        # Nombre d’alertes santé
        result = await db.execute(select(func.count()).select_from(SensorRecord).where(SensorRecord.label == 1))
        health_alerts = result.scalar()
        health_alerts_gauge.set(health_alerts)

        # Nombre d’alertes système
        result = await db.execute(select(func.count()).select_from(SystemStatus).where(
            (SystemStatus.disk_free_percent < 10) |
            (SystemStatus.update_required == True) |
            (SystemStatus.checksum_valid == False) |
            (SystemStatus.status != 1)
        ))
        system_alerts = result.scalar()
        system_alerts_gauge.set(system_alerts)

    except Exception as e:
        logger.error(f"Prometheus metrics error: {e}")

    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Metrics dashboard
@app.get("/dashboard/metrics", response_class=HTMLResponse)
async def metrics_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "it_admin" not in roles and "doctor" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Access denied to the metrics dashboard."
        })

    # Métriques communes
    result = await db.execute(select(func.count(func.distinct(SensorRecord.device_id))))
    active = result.scalar()

    # Initialisation
    sys_count = -1
    sensor_count = -1
    health_alerts = -1
    system_alerts = -1

    if "it_admin" in roles:
        result = await db.execute(select(func.count()).select_from(SystemStatus))
        sys_count = result.scalar()

        result = await db.execute(select(func.count()).select_from(SystemStatus).where(
            (SystemStatus.disk_free_percent < 10) |
            (SystemStatus.update_required == True) |
            (SystemStatus.checksum_valid == False) |
            (SystemStatus.status != 1)
        ))
        system_alerts = result.scalar()

    if "doctor" in roles:
        result = await db.execute(select(func.count()).select_from(SensorRecord))
        sensor_count = result.scalar()

        result = await db.execute(select(func.count()).select_from(SensorRecord).where(SensorRecord.label == 1))
        health_alerts = result.scalar()

    return templates.TemplateResponse("metrics_dashboard.html", {
        "request": request,
        "devices": active,
        "roles": roles,
        "sensor_count": sensor_count,
        "sys_count": sys_count,
        "health_alerts": health_alerts,
        "system_alerts": system_alerts
    })