#!/usr/bin/env python3
"""
Aegis Config API - Middleware service for API key authentication and config retrieval
Returns tenant-specific Supabase configuration and quality gate settings
"""

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import httpx
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Aegis Config API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
MASTER_SUPABASE_URL = os.getenv("MASTER_SUPABASE_URL", "")
MASTER_SUPABASE_KEY = os.getenv("MASTER_SUPABASE_KEY", "")

if not MASTER_SUPABASE_URL or not MASTER_SUPABASE_KEY:
    raise ValueError("MASTER_SUPABASE_URL and MASTER_SUPABASE_KEY must be set")

# Supabase client headers
SUPABASE_HEADERS = {
    "apikey": MASTER_SUPABASE_KEY,
    "Authorization": f"Bearer {MASTER_SUPABASE_KEY}",
    "Content-Type": "application/json"
}


class ConfigResponse(BaseModel):
    """Response model for config endpoint"""
    tenant_id: str
    supabase_url: str
    supabase_service_key: str
    quality_gates: dict
    subscription_tier: str
    status: str = "success"


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str
    status: str = "error"


def get_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Extract API key from header"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required. Provide X-API-Key header")
    return x_api_key


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "aegis-config-api"}


@app.get("/v1/config", response_model=ConfigResponse)
async def get_config(api_key: str = Depends(get_api_key)):
    """
    Get tenant configuration by API key
    
    Returns:
    - supabase_url: Tenant's Supabase project URL
    - supabase_service_key: Tenant's Supabase service role key
    - quality_gates: Quality gate configuration for CI/CD
    - subscription_tier: Tenant's subscription tier
    """
    try:
        # Query tenants table for API key
        response = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/tenants",
            headers=SUPABASE_HEADERS,
            params={"api_key": f"eq.{api_key}", "select": "*"}
        )
        
        if response.status_code != 200:
            logger.error(f"Supabase query failed: {response.status_code}")
            raise HTTPException(status_code=500, detail="Failed to query tenant database")
        
        tenants = response.json()
        
        if not tenants or len(tenants) == 0:
            logger.warning(f"Invalid API key: {api_key[:8]}...")
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        tenant = tenants[0]
        
        # Extract config from tenant record
        config_supabase_url = tenant.get("config_supabase_url")
        config_supabase_service_key = tenant.get("config_supabase_service_key")
        quality_gates = tenant.get("quality_gates", {})
        subscription_tier = tenant.get("subscription_tier", "free")
        
        # If no custom config, default to master database
        if not config_supabase_url or not config_supabase_service_key:
            logger.info(f"Tenant {tenant.get('id')} using master database (no custom config)")
            config_supabase_url = MASTER_SUPABASE_URL
            config_supabase_service_key = MASTER_SUPABASE_KEY
        
        # Log successful config retrieval
        logger.info(f"Config retrieved for tenant: {tenant.get('name', 'Unknown')} (ID: {tenant.get('id')}) - Using: {'Master DB' if config_supabase_url == MASTER_SUPABASE_URL else 'Custom DB'}")
        
        return ConfigResponse(
            tenant_id=str(tenant.get("id")),
            supabase_url=config_supabase_url,
            supabase_service_key=config_supabase_service_key,
            quality_gates=quality_gates if isinstance(quality_gates, dict) else {},
            subscription_tier=subscription_tier
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/v1/quality-gates/{tenant_id}")
async def get_quality_gates(tenant_id: str, api_key: str = Depends(get_api_key)):
    """Get quality gate configuration for a tenant"""
    try:
        response = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/tenants",
            headers=SUPABASE_HEADERS,
            params={"id": f"eq.{tenant_id}", "api_key": f"eq.{api_key}"}
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to query tenant")
        
        tenants = response.json()
        if not tenants:
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        quality_gates = tenants[0].get("quality_gates", {})
        return {"quality_gates": quality_gates}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching quality gates: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

