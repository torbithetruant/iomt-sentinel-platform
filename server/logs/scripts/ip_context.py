from ipaddress import ip_address, ip_network
import geoip2.database

# Chargement en mémoire une seule fois

reader = geoip2.database.Reader("database/GeoLite2-City.mmdb")

def get_ip_location(ip: str) -> str:
    try:
        response = reader.city(ip)
        city = response.city.name or "-"
        country = response.country.iso_code or "-"
        return f"{city}, {country}"
    except Exception:
        return "Unknown"

def is_private_ip(ip: str) -> bool:
    try:
        return ip_address(ip) in ip_network("192.168.0.0/16") \
            or ip_address(ip) in ip_network("10.0.0.0/8") \
            or ip_address(ip) in ip_network("172.16.0.0/12")
    except:
        return False