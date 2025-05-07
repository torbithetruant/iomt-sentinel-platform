# 🛡️ IoMT Sentinel Platform

**IoMT Sentinel** est une plateforme sécurisée de supervision de capteurs médicaux (réels ou simulés), combinant :

- **FastAPI** pour le backend
- **Keycloak** pour la gestion des identités et rôles
- **NGINX** pour le proxy HTTPS + sécurité
- **Machine Learning** (Random Forest, Isolation Forest) pour la détection d’anomalies
- **Dashboards dynamiques** avec Jinja2 + Chart.js
- **Prometheus** pour exporter des métriques de supervision

---

## 🔍 Fonctionnalités

- Authentification JWT avec rôles (`patient`, `doctor`, `it_admin`)
- Envoi de données santé et système par 100 capteurs simulés
- Détection automatique d’anomalies (modèles ML supervisés)
- Tableaux de bord filtrés selon le rôle
- Export Prometheus (`/metrics`) et dashboard `metrics`
- Logs applicatifs complets (accès, anomalies, erreurs, connexions)
- Surveillance système par NGINX avec health-check

---

## 🚀 Lancement rapide

1. Suivre le guide complet dans [`INSTALL.md`](INSTALL.md)
2. Démarrer Keycloak (`./config/keycloak.sh`)
3. Lancer le backend FastAPI
4. Lancer les capteurs simulés (`python sensors/simulator_multi.py`)
5. Accéder à : [https://localhost:8000](https://localhost:8000)

---

## 🧠 Modèles de Machine Learning

Deux modèles sont entraînés automatiquement :

- **RandomForestClassifier** : données capteurs santé et données système (disque, MAJ, checksum)

Les scores d’anomalie sont exportables, et un futur LLM pourra superviser ou ajuster les décisions.

---

## 🔐 Sécurité

- Certificats TLS via OpenSSL (certificat local autosigné)
- Authentification JWT
- Limitation de débit (SlowAPI)
- Logs détaillés : accès, erreurs, alertes
- Accès par rôle
- NGINX avec redirection HTTPS + Health-check

---

## ✅ Dashboard par rôle

| Rôle       | URL                         | Contenu                                  |
|------------|-----------------------------|------------------------------------------|
| `doctor`   | `/dashboard/doctor`         | Signes vitaux des patients               |
| `it_admin` | `/dashboard/system`         | État système des capteurs                |
| `it_admin` | `/dashboard/metrics`        | Prometheus : nombre de devices, etc.     |

---

## 🛠️ Contribuer

- Ajouter un LLM superviseur via `/ml/supervisor.py`
- Intégrer Grafana pour la visualisation
- Ajouter une base NoSQL pour scaler
- Étendre les types de capteurs

---

## 📃 Licence

Ce projet est open-source, libre pour usage académique ou R&D.

---

**Développé pour un projet de recherche en cybersécurité des IoMT.**
