"""
Security Middleware for VigilEdge WAF
Intercepts all requests and applies security checks
"""

import time
from typing import Callable
import json

# Import types (will work once dependencies are installed)
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response, JSONResponse
except ImportError:
    BaseHTTPMiddleware = object
    Request = object
    Response = object
    JSONResponse = object

from ..core.waf_engine import WAFEngine


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware that processes all HTTP requests through the WAF engine
    """
    
    def __init__(self, app, waf_engine: WAFEngine):
        super().__init__(app)
        self.waf_engine = waf_engine
        
        # Paths that bypass WAF checks
        self.bypass_paths = {
            "/health",
            "/docs", 
            "/redoc",
            "/openapi.json",
            "/ws",
            "/favicon.ico",
            "/login",
            "/logout"
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through WAF security checks"""
        start_time = time.time()
        
        # Skip WAF checks for certain paths
        if request.url.path in self.bypass_paths:
            response = await call_next(request)
            return response
        
        # Skip WAF checks for internal API endpoints (except test endpoints)
        if (request.url.path.startswith("/api/v1/") and 
            not request.url.path.startswith("/api/v1/test/")):
            response = await call_next(request)
            return response
        
        try:
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # Get request data
            method = request.method
            url = str(request.url)
            headers = dict(request.headers)
            
            # Get request body for POST/PUT requests
            body = None
            if method in ["POST", "PUT", "PATCH"]:
                try:
                    body_bytes = await request.body()
                    body = body_bytes.decode('utf-8') if body_bytes else None
                except Exception:
                    body = None
            
            # Process through WAF engine
            allowed, security_event = await self.waf_engine.process_request(
                method=method,
                url=url,
                headers=headers,
                body=body,
                client_ip=client_ip
            )
            
            # Block request if not allowed
            if not allowed:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by VigilEdge WAF",
                        "reason": security_event.threat_type,
                        "event_id": security_event.id,
                        "timestamp": security_event.timestamp.isoformat(),
                        "details": "Your request has been identified as potentially malicious"
                    },
                    headers={
                        "X-WAF-Status": "BLOCKED",
                        "X-WAF-Event-ID": security_event.id,
                        "X-WAF-Threat-Type": security_event.threat_type,
                    }
                )
            
            # Process request normally
            response = await call_next(request)
            
            # Add WAF headers to response
            response.headers["X-WAF-Status"] = "ALLOWED"
            response.headers["X-WAF-Event-ID"] = security_event.id
            response.headers["X-WAF-Engine"] = "VigilEdge-1.0.0"
            
            # Log processing time
            processing_time = time.time() - start_time
            response.headers["X-WAF-Processing-Time"] = f"{processing_time:.3f}s"
            
            return response
            
        except Exception as e:
            # Log error and allow request to proceed (fail-open for availability)
            print(f"WAF middleware error: {e}")
            
            try:
                response = await call_next(request)
                response.headers["X-WAF-Status"] = "ERROR"
                response.headers["X-WAF-Error"] = "Processing error occurred"
                return response
            except Exception:
                # Return error response if everything fails
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": "WAF processing error",
                        "message": "Unable to process security checks"
                    }
                )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request"""
        # Check for IP in various headers (reverse proxy scenarios)
        headers_to_check = [
            "X-Forwarded-For",
            "X-Real-IP", 
            "X-Forwarded-Host",
            "CF-Connecting-IP",  # Cloudflare
            "True-Client-IP",    # CloudFlare
        ]
        
        for header in headers_to_check:
            if header.lower() in request.headers:
                ip = request.headers[header.lower()].split(",")[0].strip()
                if ip and ip != "unknown":
                    return ip
        
        # Fall back to direct client host
        try:
            return request.client.host if request.client else "unknown"
        except AttributeError:
            return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware for additional protection
    """
    
    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_counts = {}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply rate limiting"""
        client_ip = self._get_client_ip(request)
        current_time = time.time()
        
        # Clean old entries
        self._cleanup_old_entries(current_time)
        
        # Check rate limit
        if client_ip in self.request_counts:
            if len(self.request_counts[client_ip]) >= self.max_requests:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "message": f"Maximum {self.max_requests} requests per {self.window_seconds} seconds",
                        "retry_after": self.window_seconds
                    },
                    headers={
                        "Retry-After": str(self.window_seconds),
                        "X-RateLimit-Limit": str(self.max_requests),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(current_time + self.window_seconds))
                    }
                )
        
        # Record request
        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = []
        
        self.request_counts[client_ip].append(current_time)
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        remaining = max(0, self.max_requests - len(self.request_counts.get(client_ip, [])))
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(current_time + self.window_seconds))
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address"""
        try:
            return request.client.host if request.client else "unknown"
        except AttributeError:
            return "unknown"
    
    def _cleanup_old_entries(self, current_time: float):
        """Remove old request entries outside the time window"""
        cutoff_time = current_time - self.window_seconds
        
        for ip in list(self.request_counts.keys()):
            self.request_counts[ip] = [
                req_time for req_time in self.request_counts[ip]
                if req_time > cutoff_time
            ]
            
            # Remove empty lists
            if not self.request_counts[ip]:
                del self.request_counts[ip]


class CORSSecurityMiddleware(BaseHTTPMiddleware):
    """
    Enhanced CORS middleware with security considerations
    """
    
    def __init__(self, app, allowed_origins=None, max_age=600):
        super().__init__(app)
        self.allowed_origins = allowed_origins or ["http://localhost:3000", "http://127.0.0.1:3000"]
        self.max_age = max_age
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply secure CORS headers"""
        
        # Handle preflight requests
        if request.method == "OPTIONS":
            return self._handle_preflight(request)
        
        # Process normal request
        response = await call_next(request)
        
        # Add CORS headers
        origin = request.headers.get("origin")
        if origin in self.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
        
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-Requested-With"
        response.headers["Access-Control-Max-Age"] = str(self.max_age)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response
    
    def _handle_preflight(self, request: Request) -> Response:
        """Handle CORS preflight requests"""
        origin = request.headers.get("origin")
        
        if origin not in self.allowed_origins:
            return JSONResponse(
                status_code=403,
                content={"error": "CORS policy violation"}
            )
        
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Requested-With",
                "Access-Control-Max-Age": str(self.max_age),
            }
        )
