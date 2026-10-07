from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
import time

app = FastAPI(title="Demo Target API")

# Simple in-memory rate limiting for demonstration
request_log = {}

RATE_LIMIT = 4
WINDOW_SECONDS = 30


def check_rate_limit(request: Request):
    client_ip = request.client.host

    now = time.time()

    if client_ip not in request_log:
        request_log[client_ip] = []

    # Keep only requests from the current 10-second window
    request_log[client_ip] = [
        request_time
        for request_time in request_log[client_ip]
        if now - request_time < WINDOW_SECONDS
    ]

    if len(request_log[client_ip]) >= RATE_LIMIT:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"}
        )

    request_log[client_ip].append(now)
    return None


@app.get("/users")
def users(request: Request):
    rate_limit_response = check_rate_limit(request)

    if rate_limit_response:
        return rate_limit_response

    return {"users": ["Alice", "Bob"]}


@app.get("/products")
def products(request: Request):
    rate_limit_response = check_rate_limit(request)

    if rate_limit_response:
        return rate_limit_response

    return {"products": ["Laptop", "Phone"]}


@app.get("/admin")
def admin(
    request: Request,
    authorization: str | None = Header(default=None)
):
    rate_limit_response = check_rate_limit(request)

    if rate_limit_response:
        return rate_limit_response

    # Authentication
    if authorization != "Bearer demo-admin-token":
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    # Authorization
    if authorization != "Bearer demo-admin-token":
        raise HTTPException(
            status_code=403,
            detail="Authorization failed"
        )

    return {"message": "Admin endpoint"}