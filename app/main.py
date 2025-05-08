import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.auth.auth0 import AuthError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Create FastAPI application
app = FastAPI(
    title="REanna Router API",
    description="Property Tour Management System API",
    version="0.1.0"
)

# Configure CORS for Auth0
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Local development frontend
        "https://app.reanna-router.com"  # Production frontend
    ],  
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Add exception handlers for auth errors
@app.exception_handler(AuthError)
async def handle_auth_error(request: Request, exc: AuthError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.error}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": str(exc)}
    )

@app.get("/")
async def root():
    return {"message": "Welcome to REanna Router API. See /docs for API documentation."}

# Import and include API routers
# These will be implemented in later steps
# from app.api.routes import tours, property_visits, tasks, feedback

# app.include_router(tours.router, prefix="/api/tours", tags=["tours"])
# app.include_router(property_visits.router, prefix="/api/visits", tags=["visits"])
# app.include_router(tasks.router, prefix="/api/tasks", tags=["tasks"])
# app.include_router(feedback.router, prefix="/api/feedback", tags=["feedback"])
