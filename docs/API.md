# OpenSpective REST API Documentation

Base URL: `/api/v1`  
All requests and responses use `application/json` unless otherwise specified. Authentication is provided via `Authorization: Bearer <token>`.

---

## 1. Authentication Endpoints

### `POST /api/v1/auth/signup`
Creates a new user account.
```json
// Request Body
{
  "email": "analyst@example.com",
  "password": "SecurePassword123!",
  "displayName": "Lead Investigator"
}

// Response (201 Created)
{
  "user": {
    "id": "usr_948f2190",
    "email": "analyst@example.com",
    "displayName": "Lead Investigator"
  },
  "token": "eyJhbGciOi..."
}
```

### `POST /api/v1/auth/login`
Authenticates with credentials and returns a JWT token.

### `GET /api/v1/auth/me`
Returns details of the currently authenticated user session.

---

## 2. Classification & Discovery

### `POST /api/v1/classify`
Classifies a raw string into a normalized target type.
```json
// Request
{ "input": "https://api.internal.example.com:8443/status" }

// Response (200 OK)
{
  "targetType": "url",
  "normalizedTarget": "https://api.internal.example.com:8443/status",
  "confidence": "high",
  "alternatives": ["domain"],
  "validationMessage": null,
  "isAmbiguous": false
}
```

### `GET /api/v1/modules`
Returns all registered collectors, descriptions, requirements, and current configuration status.

---

## 3. Investigation Lifecycle

### `POST /api/v1/investigations`
Initiates a new investigation.
```json
// Request
{
  "target": "cloudflare.com",
  "targetType": "domain",
  "modules": ["dns", "rdap", "certificate"],
  "enableAi": true
}

// Response (201 Created)
{
  "investigation": {
    "id": "inv_8d29b2",
    "target": "cloudflare.com",
    "target_type": "domain",
    "normalized_target": "cloudflare.com",
    "status": "queued",
    "started_at": "2026-10-13T16:00:00Z"
  },
  "classifiedAs": "domain",
  "availableModules": [...],
  "unavailableModules": [...]
}
```

### `GET /api/v1/investigations`
Lists investigations for the current user. Supports `?page=1&pageSize=20`.

### `GET /api/v1/investigations/:id`
Retrieves investigation status, timings, and collector execution progress.

### `POST /api/v1/investigations/:id/cancel`
Requests cancellation of an ongoing investigation.

---

## 4. Findings & Intelligence Graph

### `GET /api/v1/investigations/:id/findings`
Returns paginated findings for an investigation.
- Query Parameters: `category` (optional), `page`, `pageSize`.

### `GET /api/v1/investigations/:id/graph`
Returns correlated nodes and edges for visual rendering.
```json
// Response (200 OK)
{
  "nodes": [
    { "id": "domain:cloudflare.com", "type": "domain", "value": "cloudflare.com", "label": "cloudflare.com" },
    { "id": "ip:104.16.132.229", "type": "ip", "value": "104.16.132.229", "label": "104.16.132.229" }
  ],
  "edges": [
    {
      "id": "rel_182390",
      "source": "domain:cloudflare.com",
      "target": "ip:104.16.132.229",
      "type": "resolves_to",
      "label": "resolves to",
      "confidence": "high",
      "isInferred": false,
      "sourceUrl": "https://cloudflare-dns.com/dns-query"
    }
  ],
  "investigationId": "inv_8d29b2",
  "generatedAt": "2026-10-13T16:00:05Z"
}
```

---

## 5. Reports & AI Synthesis

### `POST /api/v1/investigations/:id/analyze`
Generates evidence-grounded summary via Cloudflare Workers AI.

### `POST /api/v1/investigations/:id/reports`
Generates downloadable reports in `json`, `csv`, or `html` format.
- Query parameter: `format=json|csv|html`.

### `GET /api/v1/account/usage`
Returns monthly quota status and telemetry for the current user.
