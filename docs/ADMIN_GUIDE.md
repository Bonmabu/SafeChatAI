# SafeChat AI SOC — Administrator Guide

## Overview

This guide is intended for system administrators responsible for deploying, maintaining, monitoring, and securing the SafeChat AI Security Operations Center (SOC).

---

# System Requirements

## Minimum

* Windows 10/11, Linux, or macOS
* Docker Desktop
* Docker Compose
* 8 GB RAM
* 4 CPU cores
* 20 GB free storage

## Recommended

* 16 GB RAM
* 8 CPU cores
* SSD storage
* Internet connection
* Reverse proxy (Nginx or Traefik)
* HTTPS certificate

---

# Default Ports

| Service     | Port |
| ----------- | ---- |
| Frontend    | 3000 |
| Backend API | 8000 |

---

# Project Structure

```
SafeChatAI/

frontend/
docs/
Dockerfile
docker-compose.yml
main.py
db.py
SafeChatAI.db
requirements.txt
.env.production
```

---

# Starting the System

Start all services:

```bash
docker compose up -d
```

---

# Stop the System

```bash
docker compose down
```

---

# Restart the System

```bash
docker compose restart
```

Restart a single service:

```bash
docker restart safechatai-api

docker restart safechatai-frontend
```

---

# View Running Containers

```bash
docker ps
```

---

# View Logs

Backend

```bash
docker logs safechatai-api
```

Frontend

```bash
docker logs safechatai-frontend
```

Live logs

```bash
docker compose logs -f
```

---

# Rebuild After Updates

```bash
docker compose down

docker compose build --no-cache

docker compose up -d
```

---

# Environment Configuration

Production settings are stored in

```
.env.production
```

Important variables

```
SECRET_KEY
API_KEY
DATABASE_PATH
FRONTEND_URL
ACCESS_TOKEN_EXPIRE_MINUTES
ADMIN_PASSWORD
ANALYST_PASSWORD
CUSTOMER_PASSWORD
VIEWER_PASSWORD
```

Never commit this file to a public repository.

---

# Database

Default database

```
SafeChatAI.db
```

---

# Backup Database

Windows PowerShell

```powershell
Copy-Item .\SafeChatAI.db .\Backups\SafeChatAI_Backup.db
```

Linux

```bash
cp SafeChatAI.db backups/
```

---

# Restore Database

Replace the current database with a backup.

Restart the API container afterward.

---

# Updating SafeChat AI

1. Stop containers

```bash
docker compose down
```

2. Replace project files

3. Rebuild

```bash
docker compose build --no-cache
```

4. Start

```bash
docker compose up -d
```

---

# Security Recommendations

* Change all default passwords.
* Replace placeholder SECRET_KEY with a long random value.
* Replace API_KEY with a secure key.
* Enable HTTPS before public deployment.
* Restrict server firewall access.
* Perform regular database backups.
* Monitor Docker logs for unusual activity.
* Keep Docker images updated.

---

# Health Checks

API

```
http://localhost:8000/health
```

Frontend

```
http://localhost:3000
```

---

# Troubleshooting

## API not starting

Check:

```bash
docker logs safechatai-api
```

Verify:

* DATABASE_PATH
* SECRET_KEY
* Python dependencies

---

## Frontend unavailable

Check:

```bash
docker logs safechatai-frontend
```

Verify:

* Port 3000
* Docker container status
* Frontend build completed successfully

---

## Database errors

Verify

```
SafeChatAI.db
```

exists and is writable.

---

## Login failures

Verify:

* Passwords in `.env.production`
* JWT secret
* API is running

---

## WebSocket issues

Verify:

* Port 8000 is reachable
* WebSocket endpoint is enabled
* Browser console for connection errors

---

# Maintenance Checklist

Daily

* Review alerts
* Check logs
* Verify system health

Weekly

* Backup database
* Review incidents
* Check disk usage

Monthly

* Update Docker images
* Rotate secrets if required
* Review user accounts
* Archive old reports

---

# Support

SafeChat AI SOC

Administrator Documentation

Version: Beta v1

Release Date: July 2026
