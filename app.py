#!/usr/bin/env python3
"""
Aegis Config API - Middleware service for authentication, config retrieval, and result storage
Handles JWT authentication, quality gate configuration, and scan result storage
"""

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
import os
import httpx
from datetime import datetime, timedelta
import logging
import jwt
import bcrypt
import secrets
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Aegis Config API", version="2.0.0")

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
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

if not MASTER_SUPABASE_URL or not MASTER_SUPABASE_KEY:
    raise ValueError("MASTER_SUPABASE_URL and MASTER_SUPABASE_KEY must be set")

# Supabase client headers
SUPABASE_HEADERS = {
    "apikey": MASTER_SUPABASE_KEY,
    "Authorization": f"Bearer {MASTER_SUPABASE_KEY}",
    "Content-Type": "application/json"
}

# Pydantic models
class ConfigResponse(BaseModel):
    tenant_id: str
    supabase_url: str
    supabase_service_key: str
    quality_gates: dict
    subscription_tier: str
    status: str = "success"

class QualityGateResponse(BaseModel):
    quality_gates: dict
    tenant_id: str
    status: str = "success"

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str
    expires_in: int

class StoreResultsRequest(BaseModel):
    timestamp: str
    scan_type: str
    target_path: str
    results: dict
    metadata: dict
    status: str
    quality_gate_passed: bool
    quality_gate_reasons: list

# Helper functions
def get_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Extract API key from header"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required. Provide X-API-Key header")
    return x_api_key

def verify_jwt_token(token: str) -> dict:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_jwt_token(authorization: Optional[str] = Header(None)):
    """Extract JWT token from Authorization header"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format. Use 'Bearer <token>'")
    
    token = authorization.replace("Bearer ", "")
    return verify_jwt_token(token)

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_api_key() -> str:
    """Generate a secure API key"""
    return f"aegis_{secrets.token_urlsafe(24)}"

# Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "aegis-config-api", "version": "2.0.0"}

@app.post("/v1/register", response_model=TokenResponse)
async def register(request: RegisterRequest):
    """Register a new tenant and return JWT token"""
    try:
        # Check if email already exists
        response = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/users",
            headers=SUPABASE_HEADERS,
            params={"email": f"eq.{request.email}", "select": "id"}
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to query user database")
        
        existing_users = response.json()
        if existing_users:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create tenant
        tenant_id = str(uuid.uuid4())
        api_key = generate_api_key()
        
        tenant_response = httpx.post(
            f"{MASTER_SUPABASE_URL}/rest/v1/tenants",
            headers=SUPABASE_HEADERS,
            json={
                "id": tenant_id,
                "name": request.name,
                "api_key": api_key,
                "subscription_tier": "free"
            }
        )
        
        if tenant_response.status_code not in [200, 201]:
            logger.error(f"Failed to create tenant: {tenant_response.text}")
            raise HTTPException(status_code=500, detail="Failed to create tenant")
        
        # Create user
        hashed_password = hash_password(request.password)
        user_response = httpx.post(
            f"{MASTER_SUPABASE_URL}/rest/v1/users",
            headers=SUPABASE_HEADERS,
            json={
                "id": str(uuid.uuid4()),
                "email": request.email,
                "password_hash": hashed_password,
                "tenant_id": tenant_id
            }
        )
        
        if user_response.status_code not in [200, 201]:
            logger.error(f"Failed to create user: {user_response.text}")
            # Rollback tenant creation
            httpx.delete(
                f"{MASTER_SUPABASE_URL}/rest/v1/tenants",
                headers=SUPABASE_HEADERS,
                params={"id": f"eq.{tenant_id}"}
            )
            raise HTTPException(status_code=500, detail="Failed to create user")
        
        # Generate JWT token
        expires = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        token_payload = {
            "sub": request.email,
            "tenant_id": tenant_id,
            "exp": expires,
            "iat": datetime.utcnow()
        }
        access_token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        logger.info(f"New tenant registered: {request.email} (tenant_id: {tenant_id})")
        
        return TokenResponse(
            access_token=access_token,
            tenant_id=tenant_id,
            expires_in=JWT_EXPIRATION_HOURS * 3600
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/v1/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """Login and return JWT token"""
    try:
        # Get user by email
        response = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/users",
            headers=SUPABASE_HEADERS,
            params={"email": f"eq.{request.email}", "select": "id,password_hash,tenant_id"}
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to query user database")
        
        users = response.json()
        if not users:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        user = users[0]
        
        # Verify password
        if not verify_password(request.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        # Generate JWT token
        expires = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        token_payload = {
            "sub": request.email,
            "tenant_id": user["tenant_id"],
            "exp": expires,
            "iat": datetime.utcnow()
        }
        access_token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        logger.info(f"User logged in: {request.email} (tenant_id: {user['tenant_id']})")
        
        return TokenResponse(
            access_token=access_token,
            tenant_id=user["tenant_id"],
            expires_in=JWT_EXPIRATION_HOURS * 3600
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/v1/quality-gates", response_model=QualityGateResponse)
async def get_quality_gates(api_key: str = Depends(get_api_key)):
    """Get quality gate configuration by API key"""
    try:
        response = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/tenants",
            headers=SUPABASE_HEADERS,
            params={"api_key": f"eq.{api_key}", "select": "id,quality_gates"}
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to query tenant database")
        
        tenants = response.json()
        
        if not tenants or len(tenants) == 0:
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        tenant = tenants[0]
        quality_gates = tenant.get("quality_gates", {})
        
        return QualityGateResponse(
            quality_gates=quality_gates if isinstance(quality_gates, dict) else {},
            tenant_id=str(tenant.get("id"))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching quality gates: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/v1/store-results")
async def store_results(request: StoreResultsRequest, api_key: str = Depends(get_api_key)):
    """Store scan results in database"""
    try:
        # Get tenant by API key
        tenant_response = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/tenants",
            headers=SUPABASE_HEADERS,
            params={"api_key": f"eq.{api_key}", "select": "id,config_supabase_url,config_supabase_service_key"}
        )
        
        if tenant_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to query tenant")
        
        tenants = tenant_response.json()
        if not tenants:
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        tenant = tenants[0]
        tenant_id = tenant.get("id")
        
        # Determine which Supabase to use
        config_supabase_url = tenant.get("config_supabase_url")
        config_supabase_service_key = tenant.get("config_supabase_service_key")
        
        if not config_supabase_url or not config_supabase_service_key:
            config_supabase_url = MASTER_SUPABASE_URL
            config_supabase_service_key = MASTER_SUPABASE_KEY
        
        # Store results
        storage_headers = {
            "apikey": config_supabase_service_key,
            "Authorization": f"Bearer {config_supabase_service_key}",
            "Content-Type": "application/json"
        }
        
        store_response = httpx.post(
            f"{config_supabase_url}/rest/v1/scan_results",
            headers=storage_headers,
            json={
                "tenant_id": tenant_id,
                "scan_type": request.scan_type,
                "target_path": request.target_path,
                "results": request.results,
                "metadata": request.metadata,
                "status": request.status,
                "timestamp": request.timestamp,
                "quality_gate_passed": request.quality_gate_passed,
                "quality_gate_reasons": request.quality_gate_reasons
            }
        )
        
        if store_response.status_code not in [200, 201]:
            logger.error(f"Failed to store results: {store_response.text}")
            raise HTTPException(status_code=500, detail="Failed to store results")
        
        logger.info(f"Results stored for tenant: {tenant_id}")
        
        return {"status": "success", "message": "Results stored successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error storing results: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/v1/config", response_model=ConfigResponse)
async def get_config(api_key: str = Depends(get_api_key)):
    """
    Get tenant configuration by API key (legacy endpoint, kept for compatibility)
    """
    try:
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
        
        config_supabase_url = tenant.get("config_supabase_url")
        config_supabase_service_key = tenant.get("config_supabase_service_key")
        quality_gates = tenant.get("quality_gates", {})
        subscription_tier = tenant.get("subscription_tier", "free")
        
        if not config_supabase_url or not config_supabase_service_key:
            logger.info(f"Tenant {tenant.get('id')} using master database")
            config_supabase_url = MASTER_SUPABASE_URL
            config_supabase_service_key = MASTER_SUPABASE_KEY
        
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

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
