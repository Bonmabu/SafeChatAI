# SafeChat AI SOC – Installation Guide

## Overview

This guide explains how to install and run SafeChat AI SOC using Docker.

---

## System Requirements

### Minimum

* Windows 10/11, Linux, or macOS
* Docker Desktop (or Docker Engine)
* Docker Compose
* 4 GB RAM
* 10 GB free disk space

### Recommended

* 8 GB RAM or more
* 2 CPU cores or more
* SSD storage
* Stable internet connection

---

## Project Structure

```
SafeChatAI/
├── frontend/
├── ai/
├── docs/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── main.py
├── db.py
└── SafeChatAI.db
```

---

## Environment Configuration

Create or update the `.env.production` file with your production values before deployment.

Required variables include:

* SECRET_KEY
* API_KEY
* DATABASE_PATH
* FRONTEND_URL
* ADMIN_PASSWORD
* EXECUTIVE_PASSWORD
* ANALYST_PASSWORD
* CUSTOMER_PASSWORD
* VIEWER_PASSWORD

---

## Build the Application

From the project root:

```bash
docker compose up --build -d
```

---

## Verify Containers

```bash
docker ps
```

Expected containers:

* safechatai-api
* safechatai-frontend

---

## Access the Application

Frontend:

```
http://localhost:3000
```

Backend API:

```
http://localhost:8000/docs
```

---

## Stop the Application

```bash
docker compose down
```

---

## Rebuild After Code Changes

```bash
docker compose up --build -d
```

---

## Troubleshooting

### Containers are not running

Check:

```bash
docker compose logs
```

### API unavailable

Verify the backend container is running and port 8000 is available.

### Frontend unavailable

Verify the frontend container is running and port 3000 is available.

### Database issues

Confirm that `DATABASE_PATH` points to the correct database file and matches the application configuration.

---

## Current Release

SafeChat AI SOC

**Version:** Beta v1.0
