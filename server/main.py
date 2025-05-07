from fastapi import FastAPI, Depends
from auth import require_role, get_jwt_username
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from models import SessionLocal, SensorRecord, SystemStatus, SystemRequest
from fastapi import Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.responses import RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from keycloak_file_monitor import monitor_keycloak_log
from jose import jwt
from typing import Optional
from log import logger
import os
import asyncio
import requests
import time

KEYCLOAK_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqmQj8TD7iTz+d4OFfcEym0hgMc5Q6jxp524Y/FhFCYPGntoMc+ML9kTr6hcMQdh8qRXvqd24FG1Ecgh90MWIuUYxC7hrhLr+jI5uJGwlQgsnkTnTpXGvtlf2rhbS+w+US3sQ/h2K9UsifgaH5+WSAIY95lut3AslU5zrSZeDxsMtbya10ZqYom7902OiuO81wfszO07Kk4hXSPaavo9HNyjMiIi6u+qZeQEu7kWULoCbZHOibt/Rm8yv58Issk9QRdfbp9XV2mtLYwIpVHDNFOkHAtPPeLo+JW2qmwAFIIGCgprXtwwtRROKynFaMVnMiSfaAc5bluZsv3RbLpqcBQIDAQAB
-----END PUBLIC KEY-----
"""

ALGORITHM = "RS256"
ISSUER = "http://localhost:8080/realms/iot_realm"

post = ["patient", "doctor"]

KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/iot_realm/protocol/openid-connect/token"
CLIENT_ID = "iot_backend"
CLIENT_SECRET = "VGNth5jUVhXhCx9qmgarzKPwcdhtwsF6"

LOG_PATH = "logs/server.log"

class AccessLogMiddleware(BaseHTTPMiddleware):
    EXCLUDED_PATHS = ["/favicon.ico", "/static", "/health", "/robots.txt", "/metrics", "/redirect"]

    async def dispatch(self, request: StarletteRequest, call_next):
        path = request.url.path
        # Exclure les chemins préfixés
        if any(path.startswith(excl) for excl in self.EXCLUDED_PATHS):
            return await call_next(request)

        start_time = time.time()

        ip = request.client.host
        method = request.method
        user_agent = request.headers.get("user-agent", "-")
        token = request.cookies.get("access_token")

        username = "-"
        if token:
            try:
                payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": False})
                username = payload.get("preferred_username", "-")
            except:
                pass

        response = await call_next(request)
        duration = round((time.time() - start_time) * 1000)

        logger.info(f'{ip} - {username} "{method} {path}" {response.status_code} "{user_agent}" {duration}ms')
        return response


# Utiliser cette fonction comme clé
limiter = Limiter(key_func=get_jwt_username)

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(AccessLogMiddleware)
templates = Jinja2Templates(directory="templates")

# Modèle pour les données capteurs
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

class SystemStatusData(BaseModel):
    device_id: str
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


def get_known_devices():
    db = SessionLocal()
    devices_from_sensors = db.query(SensorRecord.device_id).distinct().all()
    devices_from_system = db.query(SystemStatus.device_id).distinct().all()
    db.close()

    # Fusionner les deux sources et supprimer les doublons
    all_devices = {d[0] for d in devices_from_sensors + devices_from_system}
    return list(all_devices)


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
        return RedirectResponse(url="/login")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "roles": roles,
        "username": username
    })

@app.post("/api/sensor")
@limiter.limit("10/minute")
def receive_sensor_data(request: Request, data: SensorData, user=Depends(require_role("patient"))):

    db = SessionLocal()
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
        ecg_summary=data.ecg_summary
    )
    db.add(record)
    db.commit()
    db.close()
    logger.info(f"📡 Sensor data received from {data.device_id} by {user['preferred_username']}")
    return {"status": "ok"}


@app.post("/api/system-status")
@limiter.limit("10/minute")
def post_system_status(request: Request, data: SystemStatusData, user=Depends(require_role("patient"))):

    db = SessionLocal()
    entry = SystemStatus(
        device_id=data.device_id,
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
    db.commit()
    db.close()
    logger.info(f"💻 System status posted from {data.device_id} by {user['preferred_username']} → update_required={data.update_required}")
    return {"status": "ok"}

@app.post("/api/system-request")
@limiter.limit("10/minute")
def request_system_check(request: Request, device_id: str, user=Depends(require_role("it_admin"))):
    db = SessionLocal()
    req = SystemRequest(device_id=device_id)
    db.add(req)
    db.commit()
    db.close()
    logger.info(f"🛠️ Requested system check for {device_id}")
    return {"status": f"Demande d’état système envoyée à {device_id}"}

@app.get("/api/system-request")
@limiter.limit("10/minute")
def check_for_request(request: Request, device_id: str, user=Depends(require_role("patient"))):
    db = SessionLocal()
    req = db.query(SystemRequest)\
            .filter_by(device_id=device_id, fulfilled=False)\
            .order_by(SystemRequest.requested_at.desc())\
            .first()
    if req:
        db.close()
        logger.debug(f"📥 {device_id} checked for system request: FOUND")
        return {"request": True}
    db.close()
    logger.debug(f"📥 {device_id} checked for system request: NONE")
    return {"request": False}

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
@limiter.limit("5/minute")
def login_and_redirect(request: Request, username: str = Form(...), password: str = Form(...)):
    # 1. Obtenir le JWT depuis Keycloak
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": username,
        "password": password
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers, verify="certs/cert.pem")

    if r.status_code != 200:
        logger.warning(f"❌ Failed login for {username} from {request.client.host} ({request.headers.get('user-agent')})")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Échec de connexion : identifiants invalides."
        })

    token = r.json()["access_token"]
    logger.info(f"🔓 Successful login for {username} from {request.client.host} ({request.headers.get('user-agent')})")

    response = RedirectResponse(url="/redirect", status_code=302)
    # 🔐 Stocker le token dans un cookie sécurisé
    response.set_cookie(key="access_token", value=token, httponly=True, secure=True)  # ⚠️ mettre `secure=True` en prod
    return response

@app.get("/redirect")
def redirect_by_role(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")
    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
    except:
        return RedirectResponse(url="/login")

    return RedirectResponse(url="/")

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie("access_token")
    return response


# Script lancement du serveur
@app.on_event("startup")
async def schedule_system_requests():
    async def loop_requests():
        while True:
            db = SessionLocal()
            now = datetime.now(timezone.utc)

            # 🔁 1. Nettoyage des requêtes anciennes
            cutoff = now - timedelta(minutes=10)
            old_reqs = db.query(SystemRequest).filter(SystemRequest.fulfilled == True, SystemRequest.requested_at < cutoff)
            deleted = old_reqs.delete()
            if deleted:
                logger.info(f"🧹 {deleted} fulfilled system requests cleaned up.")

            # Nettoyer les états système vieux de 30 jours
            cutoff_sys = now - timedelta(days=30)
            old_status = db.query(SystemStatus).filter(SystemStatus.timestamp < cutoff_sys)
            deleted_sys = old_status.delete()
            if deleted_sys:
                logger.info(f"🧹 {deleted_sys} old system status entries deleted (>30d).")


            # 📡 2. Envoi de nouvelles requêtes
            for device_id in get_known_devices():
                logger.debug(f"📡 System check request sent to {device_id}")
                db.add(SystemRequest(device_id=device_id))
            db.commit()
            db.close()

            await asyncio.sleep(60)

    asyncio.create_task(loop_requests())

# @app.on_event("startup")
# async def start_background_tasks():
    # asyncio.create_task(monitor_keycloak_log())
    # asyncio.create_task(schedule_system_requests())  # ta boucle de requêtes système


# DASHBOARD

@app.get("/dashboard/doctor", response_class=HTMLResponse)
def dashboard_doctor(request: Request, device_id: str = None):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "doctor" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Vous n'avez pas les droits requis."
        })

    db = SessionLocal()

    # Liste des capteurs uniques
    all_devices = db.query(SensorRecord.device_id).distinct().all()
    device_ids = [d[0] for d in all_devices]

    # Si aucun capteur sélectionné, en prendre un par défaut
    selected_device = device_id or device_ids[0] if device_ids else None

    # Données filtrées
    records = db.query(SensorRecord).filter_by(device_id=selected_device)\
             .order_by(SensorRecord.timestamp.desc()).limit(50).all()

    db.close()

    timestamps = [r.timestamp.strftime("%H:%M:%S") for r in reversed(records)]
    heart_rates = [r.heart_rate for r in reversed(records)]
    spo2_values = [r.spo2 for r in reversed(records)]
    temp_values = [r.temperature for r in reversed(records)]
    systolic_bp = [r.systolic_bp for r in reversed(records)]
    diastolic_bp = [r.diastolic_bp for r in reversed(records)]
    respiration_rate = [r.respiration_rate for r in reversed(records)]
    glucose_level = [r.glucose_level for r in reversed(records)]
    ecg_summary = [r.ecg_summary for r in reversed(records)]

    return templates.TemplateResponse("dashboard_doctor.html", {
        "request": request,
        "timestamps": timestamps,
        "heart_rates": heart_rates,
        "spo2_values": spo2_values,
        "temp_values": temp_values,
        "systolic_bp": systolic_bp,
        "diastolic_bp": diastolic_bp,
        "respiration_rate": respiration_rate,
        "glucose_level": glucose_level,
        "ecg_summary": ecg_summary,
        "device_ids": device_ids,
        "selected_device": selected_device
    })

@app.get("/dashboard/doctor/list", response_class=HTMLResponse)
def dashboard_doctor_list(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        if "doctor" not in payload.get("realm_access", {}).get("roles", []):
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Accès refusé aux données patient."
        })

    db = SessionLocal()
    records = db.query(SensorRecord).order_by(SensorRecord.timestamp.desc()).limit(100).all()
    db.close()

    return templates.TemplateResponse("doctor_list.html", {
        "request": request,
        "records": records
    })

@app.get("/dashboard/system", response_class=HTMLResponse)
def dashboard_system(request: Request, device_id: str = None):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "it_admin" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Accès refusé à la supervision système."
        })

    db = SessionLocal()
    all_devices = db.query(SystemStatus.device_id).distinct().all()
    device_ids = [d[0] for d in all_devices]
    selected_device = device_id or device_ids[0] if device_ids else None

    records = db.query(SystemStatus)\
        .filter_by(device_id=selected_device)\
        .order_by(SystemStatus.timestamp.desc()).limit(50).all()
    db.close()

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

@app.get("/dashboard/system/list", response_class=HTMLResponse)
def dashboard_system_list(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        if "it_admin" not in payload.get("realm_access", {}).get("roles", []):
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Accès refusé aux données système."
        })

    db = SessionLocal()
    records = db.query(SystemStatus).order_by(SystemStatus.timestamp.desc()).limit(100).all()
    db.close()

    return templates.TemplateResponse("system_list.html", {
        "request": request,
        "records": records
    })

@app.get("/dashboard/logs", response_class=HTMLResponse)
def view_logs(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "it_admin" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Vous n'avez pas les droits requis pour voir les logs."
        })

    if not os.path.exists(LOG_PATH):
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Le fichier de log n'existe pas encore."
        })

    with open(LOG_PATH, "r") as f:
        log_content = f.read()[-5000:]  # dernière portion pour éviter surcharge

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "logs": log_content
    })

# Monitoring

@app.get("/health", response_class=PlainTextResponse)
def health_check():
    return "OK"

# 📊 Prometheus metrics
active_devices = Gauge("active_iomt_devices", "Nombre de capteurs uniques ayant envoyé des données")
records_total = Gauge("sensor_records_total", "Nombre total de mesures de capteurs")
system_entries = Gauge("system_status_total", "Nombre total de rapports système")

@app.get("/metrics")
def metrics():
    db = SessionLocal()
    try:
        # Nombre de capteurs uniques (présence dans la base)
        active = db.query(SensorRecord.device_id).distinct().count()
        active_devices.set(active)

        # Nombre total de données reçues
        total_sensor = db.query(SensorRecord).count()
        records_total.set(total_sensor)

        # Nombre total de statuts système
        total_system = db.query(SystemStatus).count()
        system_entries.set(total_system)
    finally:
        db.close()

    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/dashboard/metrics", response_class=HTMLResponse)
def metrics_dashboard(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")

    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if "it_admin" not in roles:
            raise Exception("Access denied")
    except:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "Accès refusé aux métriques."
        })

    db = SessionLocal()
    active = db.query(SensorRecord.device_id).distinct().count()
    sensor_count = db.query(SensorRecord).count()
    sys_count = db.query(SystemStatus).count()
    db.close()

    return templates.TemplateResponse("metrics_dashboard.html", {
        "request": request,
        "devices": active,
        "sensor_count": sensor_count,
        "sys_count": sys_count
    })
