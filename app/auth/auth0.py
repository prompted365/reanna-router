import os
import json
import time
import asyncio
import logging
from typing import Dict, List, Optional, Set, Callable, Awaitable, Any
from functools import lru_cache

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt

# Auth0 domain and API identifier from environment variables
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_API_IDENTIFIER = os.getenv("AUTH0_API_IDENTIFIER")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
ALGORITHMS = ["RS256"]

# Define namespaces for custom claims
ROLES_NAMESPACE = f"https://{AUTH0_DOMAIN}/roles"
PERMISSIONS_NAMESPACE = f"https://{AUTH0_DOMAIN}/permissions"

logger = logging.getLogger("auth.events")

class AuthError(Exception):
    """An error occurred during authentication"""
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

async def retry_with_backoff(func: Callable[..., Awaitable[Any]], max_retries=3, initial_delay=1):
    """Execute function with exponential backoff retry logic"""
    retries = 0
    delay = initial_delay
    
    while retries < max_retries:
        try:
            return await func()
        except Exception as e:
            if retries == max_retries - 1:
                raise e
            
            retries += 1
            await asyncio.sleep(delay)
            delay *= 2  # Exponential backoff

async def log_auth_event(event_type: str, user_id: str, details: Dict = None):
    """Log authentication events for security monitoring"""
    logger.info(f"Auth event: {event_type}", extra={
        "user_id": user_id,
        "timestamp": time.time(),
        "details": details or {}
    })

class Auth0JWTBearer:
    def __init__(self, domain=AUTH0_DOMAIN, audience=AUTH0_API_IDENTIFIER):
        self.domain = domain
        self.audience = audience
        self.jwks = None
        self.jwks_last_updated = 0
        self.jwks_cache_ttl = 3600  # Cache JWKS for 1 hour
        self.security = HTTPBearer(auto_error=True)
        
    async def get_jwks(self):
        """Get the JWKS from Auth0 with caching"""
        current_time = time.time()
        # Check if we need to refresh the JWKS
        if self.jwks is None or (current_time - self.jwks_last_updated > self.jwks_cache_ttl):
            jwks_url = f"https://{self.domain}/.well-known/jwks.json"
            async with httpx.AsyncClient() as client:
                try:
                    response = await retry_with_backoff(
                        lambda: client.get(jwks_url)
                    )
                    response.raise_for_status()
                    self.jwks = response.json()
                    self.jwks_last_updated = current_time
                except Exception as e:
                    raise AuthError({"code": "jwks_error", "description": f"Failed to fetch JWKS: {str(e)}"}, 500)
        return self.jwks

    async def refresh_access_token(self, refresh_token: str):
        """Exchange a refresh token for a new access token"""
        token_url = f"https://{self.domain}/oauth/token"
        payload = {
            "grant_type": "refresh_token",
            "client_id": AUTH0_CLIENT_ID,
            "client_secret": AUTH0_CLIENT_SECRET,
            "refresh_token": refresh_token
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await retry_with_backoff(
                    lambda: client.post(token_url, json=payload)
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                raise AuthError({"code": "refresh_token_error", "description": str(e)}, 500)

    async def __call__(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=True))):
        token = credentials.credentials
        
        try:
            # Get the JWKS
            jwks = await self.get_jwks()
            
            # Parse the JWT and extract header data
            unverified_header = jwt.get_unverified_header(token)
            if unverified_header.get("alg") not in ALGORITHMS:
                raise AuthError({"code": "invalid_header", "description": "Algorithm not supported"}, 401)
            
            # Find the right key
            rsa_key = {}
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"]
                    }
                    break
            
            if not rsa_key:
                raise AuthError({"code": "invalid_header", "description": "Unable to find appropriate key"}, 401)
            
            # Validate the JWT
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=self.audience,  # Exact audience match
                issuer=f"https://{self.domain}/"
            )
            
            # Check if token is expired
            if payload.get("exp") and time.time() > payload["exp"]:
                raise AuthError({"code": "token_expired", "description": "Token is expired"}, 401)
            
            # Log successful authentication
            await log_auth_event(
                "successful_authentication", 
                payload.get("sub", "unknown"),
                {"aud": payload.get("aud")}
            )
            
            # All validations passed
            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired", "description": "Token is expired"}, 401)
        except jwt.JWTClaimsError as e:
            raise AuthError({"code": "invalid_claims", "description": f"Invalid claims: {str(e)}"}, 401)
        except jwt.JWTError as e:
            raise AuthError({"code": "invalid_token", "description": f"Invalid token: {str(e)}"}, 401)
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=e.error)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Authentication error: {str(e)}")

# Instantiate auth object for use as a dependency
auth = Auth0JWTBearer()

# Helper functions for permission checking
def has_scope(required_scope: str, jwt_payload: Dict) -> bool:
    """Check if a JWT payload contains a specific scope"""
    if "scope" not in jwt_payload:
        return False
    
    # Auth0 returns scopes as a space-delimited string
    token_scopes = jwt_payload["scope"].split()
    return required_scope in token_scopes

def has_permission(required_permission: str, jwt_payload: Dict) -> bool:
    """Check if a JWT payload contains a specific permission"""
    if "permissions" not in jwt_payload:
        return False
    
    permissions = jwt_payload.get("permissions", [])
    return required_permission in permissions

def has_role(required_roles: List[str], jwt_payload: Dict) -> bool:
    """Check if a JWT payload contains any of the required roles"""
    if ROLES_NAMESPACE not in jwt_payload:
        return False
    
    user_roles = jwt_payload[ROLES_NAMESPACE]
    return any(role in user_roles for role in required_roles)

def require_scope(scope: str):
    """Decorator to require a specific scope for an endpoint"""
    def decorator(func):
        async def wrapper(*args, token=Depends(auth), **kwargs):
            if not has_scope(scope, token):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required scope: {scope}"
                )
            return await func(*args, token=token, **kwargs)
        return wrapper
    return decorator

def require_permission(permission: str):
    """Decorator to require a specific permission for an endpoint"""
    def decorator(func):
        async def wrapper(*args, token=Depends(auth), **kwargs):
            if not has_permission(permission, token):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required permission: {permission}"
                )
            return await func(*args, token=token, **kwargs)
        return wrapper
    return decorator

def require_role(roles: List[str]):
    """Decorator to require specific roles for an endpoint"""
    def decorator(func):
        async def wrapper(*args, token=Depends(auth), **kwargs):
            if not has_role(roles, token):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required roles: {', '.join(roles)}"
                )
            return await func(*args, token=token, **kwargs)
        return wrapper
    return decorator
