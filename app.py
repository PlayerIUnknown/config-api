#!/usr/bin/env python3
"""
Aegis Config API - Middleware service for authentication, config retrieval, and result storage
Handles JWT authentication, quality gate configuration, and scan result storage
"""

from fastapi import FastAPI, Header, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
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
# Security schemes for OpenAPI (/docs)
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


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

# New response models
class ScanItem(BaseModel):
    id: str
    timestamp: str
    scan_type: str
    target_path: Optional[str] = None
    status: str
    quality_gate_passed: Optional[bool] = None
    quality_gate_reasons: Optional[list] = None
    repository: Optional[dict] = None
    summary: Optional[dict] = None

class ScansListResponse(BaseModel):
    status: str = "success"
    items: list[ScanItem]
    count: int

class ScansSummaryResponse(BaseModel):
    status: str = "success"
    totals: dict
    by_status: dict
    quality_gate: dict
    last_scan_at: Optional[str] = None

class RepoCommitItem(BaseModel):
    repo_name: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    timestamp: str
    status: str
    quality_gate_passed: Optional[bool] = None
    summary: Optional[dict] = None

class ReposResponse(BaseModel):
    status: str = "success"
    items: list[RepoCommitItem]
    count: int

# Helper functions
def get_api_key(x_api_key: Optional[str] = Depends(api_key_header)):
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

def get_jwt_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)):
    """Extract JWT token from Authorization: Bearer <token>"""
    if not credentials or not credentials.scheme or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization header required")
    token = credentials.credentials
    return verify_jwt_token(token)

def _extract_repo(results: dict) -> dict:
    try:
        return (results or {}).get("metadata", {}).get("repository", {})
    except Exception:
        return {}

def _extract_summary(results: dict) -> dict:
    try:
        return (results or {}).get("summary", {})
    except Exception:
        return {}

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
                "email": request.email,
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

# =============================
# Authenticated Scan Endpoints
# =============================

@app.get("/v1/scans", response_model=ScansListResponse)
async def list_scans(
    payload: dict = Depends(get_jwt_token),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None, regex="^(running|completed|failed)$")
):
    """List complete scan details for the authenticated tenant (paginated)."""
    try:
        tenant_id = payload.get("tenant_id")
        if not tenant_id:
            raise HTTPException(status_code=401, detail="Invalid token: missing tenant_id")

        params = {
            "tenant_id": f"eq.{tenant_id}",
            "select": "id,timestamp,scan_type,target_path,status,quality_gate_passed,quality_gate_reasons,results",
            "order": "timestamp.desc",
            "limit": str(limit),
            "offset": str(offset)
        }
        if status:
            params["status"] = f"eq.{status}"

        resp = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/scan_results",
            headers=SUPABASE_HEADERS,
            params=params,
            timeout=60.0
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch scans")

        rows = resp.json() or []
        items: list[ScanItem] = []
        for r in rows:
            repo = _extract_repo(r.get("results"))
            summary = _extract_summary(r.get("results"))
            items.append(ScanItem(
                id=str(r.get("id")),
                timestamp=r.get("timestamp"),
                scan_type=r.get("scan_type"),
                target_path=r.get("target_path"),
                status=r.get("status"),
                quality_gate_passed=r.get("quality_gate_passed"),
                quality_gate_reasons=r.get("quality_gate_reasons"),
                repository=repo,
                summary=summary
            ))

        return ScansListResponse(items=items, count=len(items))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"list_scans error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/v1/scans/summary", response_model=ScansSummaryResponse)
async def scans_summary(
    payload: dict = Depends(get_jwt_token)
):
    """Aggregate summary for all scans of the authenticated tenant."""
    try:
        tenant_id = payload.get("tenant_id")
        if not tenant_id:
            raise HTTPException(status_code=401, detail="Invalid token: missing tenant_id")

        resp = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/scan_results",
            headers=SUPABASE_HEADERS,
            params={
                "tenant_id": f"eq.{tenant_id}",
                "select": "timestamp,status,quality_gate_passed,results",
                "order": "timestamp.desc",
            },
            timeout=60.0
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch scans")

        rows = resp.json() or []
        totals = {"scans": len(rows)}
        by_status = {"running": 0, "completed": 0, "failed": 0}
        qg = {"passed": 0, "failed": 0}
        last_scan_at = rows[0]["timestamp"] if rows else None

        for r in rows:
            st = r.get("status") or "completed"
            if st in by_status:
                by_status[st] += 1
            if r.get("quality_gate_passed") is True:
                qg["passed"] += 1
            elif r.get("quality_gate_passed") is False:
                qg["failed"] += 1

        return ScansSummaryResponse(
            totals=totals,
            by_status=by_status,
            quality_gate=qg,
            last_scan_at=last_scan_at
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"scans_summary error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/v1/repos", response_model=ReposResponse)
async def repos_and_commits(
    payload: dict = Depends(get_jwt_token),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Repo and commit metadata for the authenticated tenant with status and summaries."""
    try:
        tenant_id = payload.get("tenant_id")
        if not tenant_id:
            raise HTTPException(status_code=401, detail="Invalid token: missing tenant_id")

        resp = httpx.get(
            f"{MASTER_SUPABASE_URL}/rest/v1/scan_results",
            headers=SUPABASE_HEADERS,
            params={
                "tenant_id": f"eq.{tenant_id}",
                "select": "timestamp,status,results,quality_gate_passed",
                "order": "timestamp.desc",
                "limit": str(limit),
                "offset": str(offset)
            },
            timeout=60.0
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch scans")

        rows = resp.json() or []
        items: list[RepoCommitItem] = []
        for r in rows:
            repo = _extract_repo(r.get("results"))
            summary = _extract_summary(r.get("results"))
            items.append(RepoCommitItem(
                repo_name=repo.get("repo_name"),
                branch=repo.get("branch"),
                commit_hash=repo.get("commit_hash"),
                timestamp=r.get("timestamp"),
                status=r.get("status"),
                quality_gate_passed=r.get("quality_gate_passed"),
                summary=summary
            ))

        return ReposResponse(items=items, count=len(items))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"repos_and_commits error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

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
