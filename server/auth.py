from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from slowapi.util import get_remote_address
from jose import jwt, JWTError
from datetime import datetime

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

KEYCLOAK_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA69YwDPnk80OzGdp2doWI+2S0XYrmF4kkekFounifw+2h6lTNqEsGSwT8NCaAI3N/rcHxTQb17QAL3xrRdXdQiBGJmJypsl3wn+ryZCElG9i3mnRsr5R6GgNiqkf4jDDaA5leQ1wQPOl12hJTjj58X3g9ZmPVbV7PH16pCOYwhRJgs2mnCm0UajtNr4Kwzq5KhLlItE1oeQ6DvXfTEL7aEeLqW+Mx1BuQ3NPn9l9nXHs6ii3PLKyXBxcTsIEdCVKiADDRBxSsRxSPwKxgS6AflTSDwN+/Up7wS//UUqEb03xm0xiWuIF6T3tloyssx71JXijHOPG/q2KdhnqNBcy7TQIDAQAB-----END PUBLIC KEY-----
"""

ALGORITHM = "RS256"
ISSUER = "http://localhost:8080/realms/iot_realm"

ALLOWED_ROLES = ["patient", "doctor", "it_admin"]

# Fonction de clé personnalisée pour récupérer l’utilisateur depuis le JWT
def get_jwt_username(request):
    auth = request.headers.get("Authorization")
    if not auth:
        return get_remote_address(request)  # fallback IP
    try:
        token = auth.split(" ")[1]
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False})
        return payload.get("preferred_username", "anonymous")
    except Exception:
        return "unauthenticated"

def require_role(*allowed_roles):
    def wrapper(token: str = Depends(oauth2_scheme)):
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM], options={"verify_aud": False, "verify_iss": True})
        roles = payload.get("realm_access", {}).get("roles", [])
        if not any(role in roles for role in allowed_roles):
            raise HTTPException(status_code=403, detail="Access denied")
        if payload.get("exp") < datetime.now().timestamp():
            raise HTTPException(status_code=403, detail="Token expired")
        return payload
    return wrapper

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(
            token,
            KEYCLOAK_PUBLIC_KEY,
            algorithms=[ALGORITHM],
            options={"verify_aud": False, "verify_iss": True}
        )

        realm_roles = payload.get("realm_access", {}).get("roles", [])
        resource_roles = payload.get("resource_access", {}).get("iot_backend", {}).get("roles", [])
        roles = list(set(realm_roles + resource_roles))

        print("✅ JWT roles:", roles)

        if not any(role in roles for role in ALLOWED_ROLES):
            raise HTTPException(status_code=403, detail="User role not allowed")

        return payload

    except JWTError as e:
        print("❌ JWT Error:", str(e))
        raise HTTPException(status_code=403, detail="Token verification failed")


