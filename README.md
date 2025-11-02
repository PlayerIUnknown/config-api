# Aegis Config API

Middleware service that authenticates API keys and returns tenant-specific Supabase configuration and quality gate settings.

## Setup

1. **Environment Variables**
   ```bash
   cp .env.example .env
   # Edit .env with your master Supabase credentials
   ```

2. **Run Locally**
   ```bash
   pip install -r requirements.txt
   uvicorn app:app --reload --port 8000
   ```

3. **Run with Docker**
   ```bash
   docker build -t aegis-config-api .
   docker run -p 8000:8000 --env-file .env aegis-config-api
   ```

## Endpoints

### `GET /v1/config`
Returns tenant configuration including Supabase credentials and quality gates.

**Headers:**
- `X-API-Key`: Tenant API key

**Response:**
```json
{
  "tenant_id": "uuid",
  "supabase_url": "https://tenant-project.supabase.co",
  "supabase_service_key": "service-role-key",
  "quality_gates": {
    "max_critical": 0,
    "max_high": 5,
    "max_medium": 20,
    "fail_on_secrets": true
  },
  "subscription_tier": "pro"
}
```

### `GET /health`
Health check endpoint.

## Deployment

Deploy to any platform supporting Python (Railway, Render, Fly.io, AWS, etc.)

