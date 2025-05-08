from fastapi import Depends, HTTPException, status
from .auth0 import auth, has_role, ROLES_NAMESPACE, AUTH0_DOMAIN

# User type dependencies
async def get_current_user(token = Depends(auth)):
    """Get the current authenticated user"""
    return token

async def get_agent(token = Depends(auth)):
    """Check if the current user is an agent"""
    # Use the correct namespace for roles based on Auth0 documentation
    roles_namespace = ROLES_NAMESPACE
    user_roles = token.get(roles_namespace, [])
    
    if not any(role in user_roles for role in ["agent", "admin"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent role required"
        )
    return token

async def get_admin(token = Depends(auth)):
    """Check if the current user is an admin"""
    # Use the correct namespace for roles based on Auth0 documentation
    roles_namespace = ROLES_NAMESPACE
    user_roles = token.get(roles_namespace, [])
    
    if "admin" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    return token

# Check resource ownership
async def check_resource_ownership(user_id: str, resource_owner_id: str, is_admin: bool = False):
    """Check if a user owns a resource or is an admin"""
    if not (user_id == resource_owner_id or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this resource"
        )
    return True
