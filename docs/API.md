# SafeChat AI SOC API Documentation

## Overview

The SafeChat AI SOC API provides REST endpoints for authentication, threat analysis, incident management, reporting, analytics, executive dashboards, and real-time monitoring.

**Base URL (Local):**

```text
http://localhost:8000
```

Interactive API documentation:

```text
http://localhost:8000/docs
```

---

# Authentication

## Login

**POST**

```text
/login
```

Authenticates a user and returns an access token.

---

# Threat Analysis

## Analyze Message

**POST**

```text
/analyze
```

Analyzes submitted content and returns:

* Threat category
* Risk score
* AI assessment

---

# Incident Management

## List Incidents

**GET**

```text
/incidents
```

Returns all incidents.

### Resolve Incident

**PUT**

```text
/incidents/{id}/resolve
```

Marks an incident as resolved.

### Investigate Incident

**PUT**

```text
/incidents/{id}/investigate
```

Marks an incident as under investigation.

### Assign Incident

**PUT**

```text
/incidents/{id}/assign
```

Assigns an incident to a security analyst.

---

# Dashboards

## Customer Dashboard

**GET**

```text
/dashboard-data
```

Returns customer dashboard data.

## Executive Dashboard

**GET**

```text
/executive/dashboard
```

Returns executive KPIs, AI insights, and security metrics.

---

# Attack Graph

**GET**

```text
/attack-graph
```

Returns nodes and links for the live attack graph.

---

# Threat Hunting

**GET**

```text
/hunt
```

Searches incidents based on a supplied query.

Example:

```text
/hunt?query=phishing
```

---

# Reports

## PDF Report

**GET**

```text
/reports/pdf
```

Downloads the current report as a PDF.

## CSV Report

**GET**

```text
/reports/csv
```

Downloads the current report as CSV.

## Reports List

**GET**

```text
/reports
```

Returns available reports.

---

# Analytics

**GET**

```text
/analytics
```

Returns:

* Threat categories
* Severity distribution
* Incident status summary

---

# AI SOC Analyst

**POST**

```text
/soc-ai
```

Generates an AI security assessment.

---

# Threat Intelligence

Provides:

* AI threat pressure
* Forecasting
* Executive recommendations
* Threat intelligence feeds

---

# Health Check

**GET**

```text
/health
```

Returns application health information.

---

# WebSocket

Real-time SOC updates:

```text
/ws/soc
```

Streams events including:

* New threats
* Attack graph updates
* Threat intelligence
* AI decisions
* Incident updates
* Executive dashboard refreshes

---

# Response Format

Typical JSON response:

```json
{
  "status": "success",
  "message": "Operation completed",
  "data": {}
}
```

---

# Authentication

Protected endpoints require a valid JWT access token.

Authorization header:

```text
Authorization: Bearer <token>
```

---

# Version

SafeChat AI SOC

Beta v1.0

July 2026
