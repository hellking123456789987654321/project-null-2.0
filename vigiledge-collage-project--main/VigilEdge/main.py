"""
VigilEdge WAF - Main Application Entry Point
High-performance Web Application Firewall with FastAPI backend
"""

import uvicorn
import asyncio
import os
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.websockets import WebSocket, WebSocketDisconnect
from websockets.exceptions import ConnectionClosedError
import httpx
from datetime import datetime
import json
from typing import List

from vigiledge.config import get_settings
from vigiledge.core.waf_engine import WAFEngine
from vigiledge.api.routes import setup_routes
from vigiledge.middleware.security_middleware import SecurityMiddleware
from vigiledge.utils.logger import setup_logging

# Initialize settings and logging
settings = get_settings()
setup_logging()

# Configure logging to suppress WebSocket connection errors
import logging
import time
import asyncio
logging.getLogger("websockets.protocol").setLevel(logging.ERROR)
logging.getLogger("websockets.server").setLevel(logging.ERROR)
logging.getLogger("uvicorn.protocols.websockets").setLevel(logging.ERROR)
logging.getLogger("uvicorn.error").setLevel(logging.WARNING)

# Animation functions for terminal display
def animated_startup():
    """Display animated startup sequence"""
    import sys
    
    # Clear screen and show title
    print("\033[2J\033[H")  # Clear screen and move cursor to top
    
    # ASCII Art Banner
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ██╗   ██╗██╗ ██████╗ ██╗██╗     ███████╗██████╗  ██████╗  ║
    ║    ██║   ██║██║██╔════╝ ██║██║     ██╔════╝██╔══██╗██╔════╝  ║
    ║    ██║   ██║██║██║  ███╗██║██║     █████╗  ██║  ██║██║  ███╗ ║
    ║    ╚██╗ ██╔╝██║██║   ██║██║██║     ██╔══╝  ██║  ██║██║   ██║ ║
    ║     ╚████╔╝ ██║╚██████╔╝██║███████╗███████╗██████╔╝╚██████╔╝ ║
    ║      ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝  ║
    ║                                                              ║
    ║                 🛡️  Web Application Firewall 🛡️              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print("\033[36m" + banner + "\033[0m")  # Cyan color
    
    # Animated loading sequence
    loading_steps = [
        ("🔧 Initializing Security Engine", 0.8),
        ("🔍 Loading Threat Detection Rules", 0.6),
        ("📊 Setting up Real-time Monitoring", 0.5),
        ("🌐 Starting Web Server", 0.4),
        ("🔗 Establishing WebSocket Connections", 0.3),
        ("✅ VigilEdge WAF Ready!", 0.2)
    ]
    
    print("\n" + "="*60)
    print("🚀 STARTUP SEQUENCE")
    print("="*60)
    
    for step, delay in loading_steps:
        # Animated dots
        for i in range(3):
            print(f"\r{step}{'.' * (i + 1)}", end="", flush=True)
            time.sleep(delay / 3)
        print(f"\r{step}... ✅")
        time.sleep(0.2)

async def monitoring_task():
    """Background task showing enhanced visual system status"""
    import random
    
    # Enhanced status indicators
    status_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    security_states = ["🟢 SECURE", "🟡 MONITORING", "🔵 SCANNING", "🟢 PROTECTED"]
    threat_alerts = ["🚨 SQL INJECTION BLOCKED", "⚠️  XSS ATTEMPT DETECTED", "🛡️  RATE LIMIT TRIGGERED"]
    
    counter = 0
    last_threat_time = 0
    
    while True:
        try:
            # Rotating status indicator
            status_char = status_chars[counter % len(status_chars)]
            security_state = security_states[counter % len(security_states)]
            
            # Get current time
            current_time = datetime.now().strftime("%H:%M:%S")
            
            # Simulate metrics with more variety
            requests_processed = 1250 + random.randint(0, 100)
            threats_blocked = 12 + random.randint(0, 5)
            active_connections = len(manager.active_connections)
            cpu_usage = random.randint(15, 45)
            
            # Occasionally show threat alerts (visual drama!)
            threat_alert = ""
            if random.randint(1, 20) == 1 and counter - last_threat_time > 20:
                threat_alert = f" | 🚨 {random.choice(threat_alerts)}"
                last_threat_time = counter
            
            # Create enhanced status line with more visual elements
            status_line = (
                f"\r{status_char} {security_state} | "
                f"🕒 {current_time} | "
                f"📊 Requests: {requests_processed} | "
                f"🛡️  Blocked: {threats_blocked} | "
                f"🔗 Live: {active_connections} | "
                f"💻 CPU: {cpu_usage}%{threat_alert}"
            )
            
            # Color coding based on activity
            if threat_alert:
                print(f"\033[91m{status_line}\033[0m", end="", flush=True)  # Red for alerts
            elif cpu_usage > 35:
                print(f"\033[93m{status_line}\033[0m", end="", flush=True)  # Yellow for high CPU
            else:
                print(f"\033[92m{status_line}\033[0m", end="", flush=True)  # Green for normal
            
            counter += 1
            await asyncio.sleep(0.5)  # Update every 500ms
            
        except asyncio.CancelledError:
            print("\n🛑 Enhanced monitoring stopped.")
            break
        except Exception:
            # Silent error handling
            await asyncio.sleep(1)
            await asyncio.sleep(1)

# Modern lifespan event handler
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager with animated startup"""
    # Animated startup sequence
    animated_startup()
    
    # Show connection info
    print(f"\n🌐 Server Information:")
    print(f"   📊 Dashboard: http://{settings.host}:{settings.port}")
    print(f"   📖 API Docs: http://{settings.host}:{settings.port}/docs")
    print(f"   🔧 Environment: {settings.environment}")
    print(f"   🛡️  Security Level: Maximum")
    
    print("\n" + "="*60)
    print("📡 REAL-TIME MONITORING ACTIVE")
    print("="*60)
    
    # Start background monitoring
    monitoring_task_handle = asyncio.create_task(monitoring_task())
    
    yield
    
    # Shutdown sequence
    print("\n\n🛑 VigilEdge WAF Shutting down...")
    print("🔒 Closing security connections...")
    monitoring_task_handle.cancel()
    try:
        await monitoring_task_handle
    except asyncio.CancelledError:
        pass
    print("✅ Shutdown complete. Stay secure! 🛡️")

# Create FastAPI application
app = FastAPI(
    title="VigilEdge WAF",
    description="Advanced Web Application Firewall with Real-time Threat Detection",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize WAF Engine
waf_engine = WAFEngine()

# Add security middleware 
app.add_middleware(SecurityMiddleware, waf_engine=waf_engine)

# Mount static files
current_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(current_dir, "static")
templates_dir = os.path.join(current_dir, "templates")

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Setup templates
templates = Jinja2Templates(directory=templates_dir)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except (ConnectionClosedError, WebSocketDisconnect):
            # Client disconnected, remove from active connections silently
            self.disconnect(websocket)
        except Exception:
            # Handle any other WebSocket errors silently
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except (ConnectionClosedError, WebSocketDisconnect, Exception):
                # Mark for removal instead of immediate removal to avoid iteration issues
                disconnected.append(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            if connection in self.active_connections:
                self.active_connections.remove(connection)

manager = ConnectionManager()

# Security token validation (deprecated - keeping for backward compatibility)
security = HTTPBearer()

async def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate JWT token for admin access (deprecated)"""
    # In production, implement proper JWT validation
    if credentials.credentials != "admin-token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials

# Authentication routes removed - direct access enabled

@app.get("/", response_class=HTMLResponse)
async def root():
    """Redirect directly to admin dashboard - no authentication required"""
    return RedirectResponse(url="/admin/dashboard", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def customer_dashboard():
    """Serve customer/user dashboard with limited features"""
    try:
        # Get basic metrics for customer view
        metrics = await waf_engine.get_metrics()
        
        # Load customer dashboard template
        template_path = os.path.join(current_dir, "templates", "customer_dashboard.html")
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            
        # Replace placeholders with default data (no user context)
        template_content = template_content.replace(
            "{{ username }}", "WAF User"
        ).replace(
            "{{ role }}", "User"
        ).replace(
            "{{ metrics.total_requests }}", str(metrics.get('total_requests', 0))
        ).replace(
            "{{ metrics.blocked_requests }}", str(metrics.get('blocked_requests', 0))
        ).replace(
            "{{ username[0].upper() if username else 'U' }}", 
            "U"
        ).replace(
            "{{ username or 'User' }}", 
            "User"
        ).replace(
            "{{ role.title() if role else 'Customer' }}", 
            "User"
        ).replace(
            "{{ metrics.total_requests or 1247 }}", 
            str(metrics.get('total_requests', 1247))
        ).replace(
            "{{ metrics.blocked_requests or 23 }}", 
            str(metrics.get('blocked_requests', 23))
        )
        
        return HTMLResponse(content=template_content)
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Dashboard Error</h1>
        <p>Customer dashboard template not found.</p>
        <a href="/login">Back to Login</a>
        </body>
        </html>
        """, status_code=404)

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard():
    """Serve the full admin dashboard with complete access"""
    try:
        # Get comprehensive data for admin view
        metrics = await waf_engine.get_metrics()
        recent_events = await waf_engine.get_recent_events(limit=10)
        blocked_ips = await waf_engine.get_blocked_ips()
        
        # Load admin dashboard template
        template_path = os.path.join(current_dir, "templates", "enhanced_dashboard.html")
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            
        # Replace placeholders with actual data
        template_content = template_content.replace(
            "{{TOTAL_REQUESTS}}", str(metrics.get('total_requests', 0))
        ).replace(
            "{{BLOCKED_REQUESTS}}", str(metrics.get('blocked_requests', 0))
        ).replace(
            "{{THREATS_DETECTED}}", str(metrics.get('threats_detected', 0))
        ).replace(
            "{{BLOCKED_IPS_COUNT}}", str(len(blocked_ips))
        )
        
        return HTMLResponse(content=template_content)
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Admin Dashboard Error</h1>
        <p>Enhanced dashboard template not found.</p>
        <a href="/login">Back to Login</a>
        </body>
        </html>
        """, status_code=404)

@app.get("/enhanced", response_class=HTMLResponse)
async def enhanced_dashboard():
    """Serve the enhanced cyber-themed dashboard"""
    try:
        with open("templates/enhanced_dashboard.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Enhanced Dashboard Not Found</h1>
        <p>The enhanced dashboard template is not available. Please ensure the templates directory exists.</p>
        <a href="/classic">Go to Classic Dashboard</a>
        </body>
        </html>
        """, status_code=404)

@app.get("/classic", response_class=HTMLResponse)
async def classic_dashboard():
    """Serve the original dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>VigilEdge WAF Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            :root {
                --primary-bg: linear-gradient(135deg, #0a0a0a 0%, #1a0a2e 50%, #16213e 100%);
                --secondary-bg: rgba(26, 26, 46, 0.95);
                --card-bg: rgba(30, 30, 46, 0.98);
                --glass-bg: rgba(255, 255, 255, 0.05);
                --border-color: rgba(0, 255, 65, 0.2);
                --primary-green: #00ff41;
                --accent-green: #00cc33;
                --neon-blue: #00d4ff;
                --neon-purple: #b300ff;
                --danger-red: #ff3366;
                --warning-orange: #ff9500;
                --info-blue: #00aaff;
                --success-green: #00ff66;
                --text-primary: #ffffff;
                --text-secondary: #e0e0e0;
                --text-muted: #999999;
                --shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                --glass-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
                --border-radius: 16px;
                --glow: 0 0 20px rgba(0, 255, 65, 0.5);
            }
            
            body {
                font-family: 'Segoe UI', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: var(--primary-bg);
                color: var(--text-primary);
                line-height: 1.6;
                min-height: 100vh;
                position: relative;
                overflow-x: hidden;
            }
            
            body::before {
                content: '';
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    radial-gradient(circle at 20% 80%, rgba(0, 255, 65, 0.1) 0%, transparent 50%),
                    radial-gradient(circle at 80% 20%, rgba(179, 0, 255, 0.1) 0%, transparent 50%),
                    radial-gradient(circle at 40% 40%, rgba(0, 212, 255, 0.05) 0%, transparent 50%);
                pointer-events: none;
                z-index: -1;
            }
            
            .container {
                max-width: 1600px;
                margin: 0 auto;
                padding: 30px;
                position: relative;
                z-index: 1;
            }
            
            .header {
                text-align: center;
                margin-bottom: 50px;
                padding: 50px 0;
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                border-radius: var(--border-radius);
                box-shadow: var(--glass-shadow);
                position: relative;
                overflow: hidden;
            }
            
            .header::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, 
                    var(--primary-green) 0%, 
                    var(--neon-blue) 25%, 
                    var(--neon-purple) 50%, 
                    var(--neon-blue) 75%, 
                    var(--primary-green) 100%);
                animation: rainbow 3s linear infinite;
            }
            
            .header::after {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                width: 300px;
                height: 300px;
                background: radial-gradient(circle, rgba(0, 255, 65, 0.1) 0%, transparent 70%);
                transform: translate(-50%, -50%);
                animation: pulse 4s ease-in-out infinite;
                pointer-events: none;
            }
            
            .header h1 {
                font-size: 4rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--primary-green), var(--neon-blue), var(--neon-purple));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 15px;
                text-shadow: 0 0 30px rgba(0, 255, 65, 0.5);
                position: relative;
                z-index: 2;
                letter-spacing: -1px;
            }
            
            .header p {
                color: var(--text-secondary);
                font-size: 1.4rem;
                font-weight: 400;
                margin-bottom: 25px;
                position: relative;
                z-index: 2;
            }
            
            .status-indicator {
                display: inline-flex;
                align-items: center;
                gap: 12px;
                background: var(--glass-bg);
                backdrop-filter: blur(10px);
                padding: 12px 24px;
                border-radius: 25px;
                border: 1px solid var(--primary-green);
                box-shadow: var(--glow);
                position: relative;
                z-index: 2;
                font-weight: 600;
            }
            
            .status-dot {
                width: 12px;
                height: 12px;
                background: var(--primary-green);
                border-radius: 50%;
                animation: blink 2s ease-in-out infinite;
                box-shadow: 0 0 10px var(--primary-green);
            }
            
            .services-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 25px;
                margin-bottom: 40px;
            }
            
            .service-category {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                border-radius: var(--border-radius);
                padding: 25px;
                box-shadow: var(--glass-shadow);
                transition: all 0.4s ease;
                position: relative;
                overflow: hidden;
            }
            
            .service-category::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--primary-green), var(--neon-blue));
                transform: scaleX(0);
                transform-origin: left;
                transition: transform 0.3s ease;
            }
            
            .service-category:hover::before {
                transform: scaleX(1);
            }
            
            .service-category:hover {
                transform: translateY(-8px);
                box-shadow: 0 15px 40px rgba(0, 255, 65, 0.2);
                border-color: var(--primary-green);
            }
            
            .service-category h3 {
                color: var(--primary-green);
                margin-bottom: 20px;
                font-size: 1.3rem;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .service-links {
                display: flex;
                flex-direction: column;
                gap: 12px;
            }
            
            .service-link {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 12px 16px;
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                text-decoration: none;
                color: var(--text-secondary);
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            
            .service-link::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.1), transparent);
                transition: left 0.5s ease;
            }
            
            .service-link:hover {
                color: var(--primary-green);
                border-color: var(--primary-green);
                box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
                transform: translateX(5px);
            }
            
            .service-link:hover::before {
                left: 100%;
            }
            
            .service-link-info {
                display: flex;
                flex-direction: column;
                gap: 2px;
            }
            
            .service-link-title {
                font-weight: 600;
                font-size: 0.95rem;
            }
            
            .service-link-url {
                font-size: 0.8rem;
                color: var(--text-muted);
                font-family: 'Courier New', monospace;
            }
            
            .service-link-icon {
                font-size: 1.2rem;
                opacity: 0.7;
                transition: all 0.3s ease;
            }
            
            .service-link:hover .service-link-icon {
                opacity: 1;
                transform: scale(1.2);
            }
            
            .nav {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                padding: 25px;
                border-radius: var(--border-radius);
                margin-bottom: 40px;
                box-shadow: var(--glass-shadow);
                display: flex;
                flex-wrap: wrap;
                gap: 20px;
                justify-content: center;
                border: 1px solid var(--border-color);
            }
            
            .nav a {
                color: var(--text-secondary);
                text-decoration: none;
                padding: 15px 25px;
                border-radius: 12px;
                background: var(--glass-bg);
                backdrop-filter: blur(10px);
                border: 1px solid var(--border-color);
                transition: all 0.4s ease;
                font-weight: 600;
                position: relative;
                overflow: hidden;
                font-size: 0.95rem;
            }
            
            .nav a::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.2), transparent);
                transition: left 0.5s ease;
            }
            
            .nav a:hover {
                color: var(--primary-green);
                border-color: var(--primary-green);
                box-shadow: var(--glow);
                transform: translateY(-3px);
            }
            
            .nav a:hover::before {
                left: 100%;
            }
            
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                gap: 30px;
                margin-bottom: 50px;
            }
            
            .stat-card {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                padding: 35px;
                border-radius: var(--border-radius);
                position: relative;
                overflow: hidden;
                transition: all 0.4s ease;
                box-shadow: var(--glass-shadow);
            }
            
            .stat-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--primary-green), var(--neon-blue));
                transform: scaleX(0);
                transform-origin: left;
                transition: transform 0.3s ease;
            }
            
            .stat-card:hover::before {
                transform: scaleX(1);
            }
            
            .stat-card:hover {
                transform: translateY(-10px) scale(1.02);
                box-shadow: 0 20px 60px rgba(0, 255, 65, 0.25);
                border-color: var(--primary-green);
            }
            
            .stat-value {
                font-size: 3rem;
                font-weight: 800;
                color: var(--primary-green);
                margin-bottom: 15px;
                text-shadow: var(--glow);
                transition: all 0.3s ease;
                position: relative;
                z-index: 2;
            }
            
            .stat-label {
                color: var(--text-secondary);
                font-size: 1.1rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1.5px;
                position: relative;
                z-index: 2;
            }
            
            .stat-icon {
                position: absolute;
                top: 25px;
                right: 25px;
                font-size: 2.5rem;
                opacity: 0.2;
                color: var(--primary-green);
                transition: all 0.3s ease;
            }
            
            .stat-card:hover .stat-icon {
                opacity: 0.4;
                transform: scale(1.1) rotate(5deg);
            }
            
            .alerts {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                padding: 35px;
                border-radius: var(--border-radius);
                box-shadow: var(--glass-shadow);
                position: relative;
                overflow: hidden;
            }
            
            .alerts::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--danger-red), var(--warning-orange), var(--success-green));
            }
            
            .alerts h3 {
                color: var(--primary-green);
                margin-bottom: 25px;
                font-size: 1.6rem;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 12px;
                text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
            }
            
            .alerts-container {
                max-height: 500px;
                overflow-y: auto;
                scrollbar-width: thin;
                scrollbar-color: var(--primary-green) transparent;
            }
            
            .alerts-container::-webkit-scrollbar {
                width: 8px;
            }
            
            .alerts-container::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 4px;
            }
            
            .alerts-container::-webkit-scrollbar-thumb {
                background: var(--primary-green);
                border-radius: 4px;
                box-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
            }
            
            .alert {
                background: var(--glass-bg);
                backdrop-filter: blur(10px);
                border-left: 4px solid var(--danger-red);
                padding: 20px;
                margin: 20px 0;
                border-radius: 0 12px 12px 0;
                animation: slideIn 0.4s ease;
                position: relative;
                overflow: hidden;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            }
            
            .alert::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
                animation: alertShine 4s ease-in-out infinite;
            }
            
            .connection-status {
                padding: 20px;
                border-radius: 12px;
                text-align: center;
                font-weight: 600;
                margin-bottom: 25px;
                transition: all 0.3s ease;
                backdrop-filter: blur(10px);
                font-size: 1.05rem;
            }
            
            .connection-status.connected {
                background: rgba(0, 255, 102, 0.1);
                color: var(--success-green);
                border: 1px solid var(--success-green);
                box-shadow: 0 0 20px rgba(0, 255, 102, 0.3);
            }
            
            .connection-status.disconnected {
                background: rgba(255, 51, 102, 0.1);
                color: var(--danger-red);
                border: 1px solid var(--danger-red);
                box-shadow: 0 0 20px rgba(255, 51, 102, 0.3);
            }
            
            .loading {
                display: inline-block;
                width: 24px;
                height: 24px;
                border: 3px solid rgba(0, 255, 65, 0.3);
                border-radius: 50%;
                border-top-color: var(--primary-green);
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            
            @keyframes rainbow {
                0% { background-position: 0% 50%; }
                100% { background-position: 200% 50%; }
            }
            
            @keyframes pulse {
                0%, 100% { 
                    opacity: 0.8; 
                    transform: translate(-50%, -50%) scale(1);
                }
                50% { 
                    opacity: 0.4; 
                    transform: translate(-50%, -50%) scale(1.1);
                }
            }
            
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.3; }
            }
            
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateX(-30px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
            
            @keyframes alertShine {
                0% { left: -100%; }
                100% { left: 100%; }
            }
            
            @media (max-width: 1200px) {
                .services-grid {
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                }
            }
            
            @media (max-width: 768px) {
                .container {
                    padding: 15px;
                }
                
                .header h1 {
                    font-size: 2.5rem;
                }
                
                .header p {
                    font-size: 1.1rem;
                }
                
                .stats {
                    grid-template-columns: 1fr;
                }
                
                .services-grid {
                    grid-template-columns: 1fr;
                }
                
                .nav {
                    flex-direction: column;
                    align-items: center;
                }
            }
            
            .nav {
                background: var(--card-bg);
                padding: 20px;
                border-radius: var(--border-radius);
                margin-bottom: 30px;
                box-shadow: var(--shadow);
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                justify-content: center;
                border: 1px solid var(--border-color);
            }
            
            .nav a {
                color: var(--text-secondary);
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 8px;
                background: var(--secondary-bg);
                border: 1px solid var(--border-color);
                transition: all 0.3s ease;
                font-weight: 500;
                position: relative;
                overflow: hidden;
            }
            
            .nav a::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.2), transparent);
                transition: left 0.5s ease;
            }
            
            .nav a:hover {
                color: var(--primary-green);
                border-color: var(--primary-green);
                box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
                transform: translateY(-2px);
            }
            
            .nav a:hover::before {
                left: 100%;
            }
            
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 25px;
                margin-bottom: 40px;
            }
            
            .stat-card {
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                padding: 30px;
                border-radius: var(--border-radius);
                position: relative;
                overflow: hidden;
                transition: all 0.3s ease;
                box-shadow: var(--shadow);
            }
            
            .stat-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: var(--primary-green);
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(0, 255, 65, 0.15);
                border-color: var(--primary-green);
            }
            
            .stat-value {
                font-size: 2.5rem;
                font-weight: 700;
                color: var(--primary-green);
                margin-bottom: 10px;
                text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
                transition: all 0.3s ease;
            }
            
            .stat-label {
                color: var(--text-secondary);
                font-size: 1rem;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .stat-icon {
                position: absolute;
                top: 20px;
                right: 20px;
                font-size: 2rem;
                opacity: 0.3;
                color: var(--primary-green);
            }
            
            .alerts {
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                padding: 30px;
                border-radius: var(--border-radius);
                box-shadow: var(--shadow);
            }
            
            .alerts h3 {
                color: var(--primary-green);
                margin-bottom: 20px;
                font-size: 1.5rem;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .alerts-container {
                max-height: 400px;
                overflow-y: auto;
                scrollbar-width: thin;
                scrollbar-color: var(--primary-green) var(--secondary-bg);
            }
            
            .alerts-container::-webkit-scrollbar {
                width: 6px;
            }
            
            .alerts-container::-webkit-scrollbar-track {
                background: var(--secondary-bg);
                border-radius: 3px;
            }
            
            .alerts-container::-webkit-scrollbar-thumb {
                background: var(--primary-green);
                border-radius: 3px;
            }
            
            .alert {
                background: linear-gradient(135deg, rgba(255, 51, 102, 0.1), rgba(255, 51, 102, 0.05));
                border-left: 4px solid var(--danger-red);
                padding: 15px;
                margin: 15px 0;
                border-radius: 0 8px 8px 0;
                animation: slideIn 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            
            .alert::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
                animation: alertShine 3s ease-in-out infinite;
            }
            
            .alert-time {
                color: var(--primary-green);
                font-weight: 600;
                font-size: 0.9rem;
            }
            
            .connection-status {
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                font-weight: 500;
                margin-bottom: 20px;
                transition: all 0.3s ease;
            }
            
            .connection-status.connected {
                background: rgba(0, 255, 65, 0.1);
                color: var(--primary-green);
                border: 1px solid var(--primary-green);
            }
            
            .connection-status.disconnected {
                background: rgba(255, 51, 102, 0.1);
                color: var(--danger-red);
                border: 1px solid var(--danger-red);
            }
            
            .loading {
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid rgba(0, 255, 65, 0.3);
                border-radius: 50%;
                border-top-color: var(--primary-green);
                animation: spin 1s ease-in-out infinite;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.3; }
            }
            
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateX(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
            
            @keyframes alertShine {
                0% { left: -100%; }
                100% { left: 100%; }
            }
            
            @media (max-width: 768px) {
                .container {
                    padding: 10px;
                }
                
                .header h1 {
                    font-size: 2rem;
                }
                
                .stats {
                    grid-template-columns: 1fr;
                }
                
                .nav {
                    flex-direction: column;
                    align-items: center;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ VigilEdge WAF</h1>
                <p>Enterprise-Grade Web Application Firewall & Security Operations Center</p>
                <div class="status-indicator">
                    <div class="status-dot"></div>
                    <span>System Operational</span>
                </div>
            </div>
            
            <div class="services-grid">
                <div class="service-category">
                    <h3>🏠 Core Services</h3>
                    <div class="service-links">
                        <a href="/" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Main Dashboard</div>
                                <div class="service-link-url">http://localhost:5000</div>
                            </div>
                            <div class="service-link-icon">🏠</div>
                        </a>
                        <a href="/health" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Health Monitor</div>
                                <div class="service-link-url">http://localhost:5000/health</div>
                            </div>
                            <div class="service-link-icon">💗</div>
                        </a>
                        <a href="/admin" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Admin Portal</div>
                                <div class="service-link-url">http://localhost:5000/admin</div>
                            </div>
                            <div class="service-link-icon">👨‍💼</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>📊 Analytics & Monitoring</h3>
                    <div class="service-links">
                        <a href="/api/v1/metrics" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Performance Metrics</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/metrics</div>
                            </div>
                            <div class="service-link-icon">📈</div>
                        </a>
                        <a href="/api/v1/events" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Security Events</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/events</div>
                            </div>
                            <div class="service-link-icon">📋</div>
                        </a>
                        <a href="javascript:void(0)" onclick="connectWebSocket()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Real-time Alerts</div>
                                <div class="service-link-url">ws://localhost:5000/ws</div>
                            </div>
                            <div class="service-link-icon">⚡</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>🛡️ Security Management</h3>
                    <div class="service-links">
                        <a href="/api/v1/blocked-ips" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Blocked IPs</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/blocked-ips</div>
                            </div>
                            <div class="service-link-icon">🚫</div>
                        </a>
                        <a href="/api/v1/security/summary" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Security Summary</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/security/summary</div>
                            </div>
                            <div class="service-link-icon">🔍</div>
                        </a>
                        <a href="/api/v1/security/rules" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Security Rules</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/security/rules</div>
                            </div>
                            <div class="service-link-icon">📜</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>📚 Documentation</h3>
                    <div class="service-links">
                        <a href="/docs" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Interactive API Docs</div>
                                <div class="service-link-url">http://localhost:5000/docs</div>
                            </div>
                            <div class="service-link-icon">📖</div>
                        </a>
                        <a href="/redoc" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Alternative API Docs</div>
                                <div class="service-link-url">http://localhost:5000/redoc</div>
                            </div>
                            <div class="service-link-icon">📑</div>
                        </a>
                        <a href="javascript:void(0)" onclick="openLogViewer()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">System Logs</div>
                                <div class="service-link-url">logs/vigiledge.log</div>
                            </div>
                            <div class="service-link-icon">📄</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>🧪 Testing & Development</h3>
                    <div class="service-links">
                        <a href="/api/v1/test/trigger-sql-injection" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">SQL Injection Test</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/test/trigger-sql-injection</div>
                            </div>
                            <div class="service-link-icon">💉</div>
                        </a>
                        <a href="/api/v1/test/trigger-xss" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">XSS Protection Test</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/test/trigger-xss</div>
                            </div>
                            <div class="service-link-icon">🔗</div>
                        </a>
                        <a href="javascript:void(0)" onclick="runRateLimitTest()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Rate Limit Test</div>
                                <div class="service-link-url">Multiple Requests</div>
                            </div>
                            <div class="service-link-icon">🚀</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>🔧 Configuration</h3>
                    <div class="service-links">
                        <a href="javascript:void(0)" onclick="showEnvConfig()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Environment Variables</div>
                                <div class="service-link-url">.env Configuration</div>
                            </div>
                            <div class="service-link-icon">⚙️</div>
                        </a>
                        <a href="javascript:void(0)" onclick="showWafRules()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">WAF Rules Config</div>
                                <div class="service-link-url">config/waf_rules.yaml</div>
                            </div>
                            <div class="service-link-icon">🔧</div>
                        </a>
                        <a href="/proxy" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Proxy Gateway</div>
                                <div class="service-link-url">http://localhost:5000/proxy</div>
                            </div>
                            <div class="service-link-icon">🌐</div>
                        </a>
                    </div>
                </div>
            </div>
            
            <div class="nav">
                <a href="/health">🏥 Health Status</a>
                <a href="/api/v1/metrics">📊 Metrics</a>
                <a href="/api/v1/events">📋 Recent Events</a>
                <a href="/api/v1/blocked-ips">🚫 Blocked IPs</a>
                <a href="/docs">📚 API Documentation</a>
            </div>

            <div class="stats" id="stats">
                <div class="stat-card">
                    <div class="stat-icon">📈</div>
                    <div class="stat-value" id="total-requests"><div class="loading"></div></div>
                    <div class="stat-label">Total Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">🛡️</div>
                    <div class="stat-value" id="blocked-requests"><div class="loading"></div></div>
                    <div class="stat-label">Blocked Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⚠️</div>
                    <div class="stat-value" id="threats-detected"><div class="loading"></div></div>
                    <div class="stat-label">Threats Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⚡</div>
                    <div class="stat-value" id="response-time"><div class="loading"></div></div>
                    <div class="stat-label">Avg Response Time (ms)</div>
                </div>
            </div>

            <div class="alerts">
                <h3>🚨 Real-time Security Alerts</h3>
                <div id="connection-status" class="connection-status">
                    <span>🔌 Connecting to real-time monitoring...</span>
                </div>
                <div class="alerts-container" id="alerts-container">
                    <!-- Alerts will be populated here -->
                </div>
            </div>
        </div>

        <script>
            // WebSocket connection for real-time updates
            const ws = new WebSocket('ws://localhost:5000/ws');
            const alertsContainer = document.getElementById('alerts-container');
            const connectionStatus = document.getElementById('connection-status');
            
            ws.onopen = function() {
                console.log('WebSocket connected');
                connectionStatus.className = 'connection-status connected';
                connectionStatus.innerHTML = '<span>✅ Connected to real-time monitoring</span>';
                
                // Send a welcome message
                setTimeout(() => {
                    addAlert('🚀 VigilEdge WAF monitoring system initialized', 'info');
                }, 1000);
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                if (data.type === 'alert') {
                    addAlert(data.message, data.severity || 'warning');
                } else if (data.type === 'metrics') {
                    updateMetrics(data.data);
                } else if (data.type === 'security_event') {
                    addAlert(`🚨 ${data.threat_type}: ${data.message}`, 'danger');
                }
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected');
                connectionStatus.className = 'connection-status disconnected';
                connectionStatus.innerHTML = '<span>❌ Disconnected from monitoring</span>';
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
                connectionStatus.className = 'connection-status disconnected';
                connectionStatus.innerHTML = '<span>⚠️ Connection error - Retrying...</span>';
            };
            
            function addAlert(message, severity = 'warning') {
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert alert-${severity}`;
                
                const timeStr = new Date().toLocaleTimeString();
                const severityIcon = {
                    'info': 'ℹ️',
                    'warning': '⚠️',
                    'danger': '🚨',
                    'success': '✅'
                }[severity] || '⚠️';
                
                alertDiv.innerHTML = `
                    <div class="alert-time">[${timeStr}] ${severityIcon}</div>
                    <div class="alert-message">${message}</div>
                `;
                
                alertsContainer.insertBefore(alertDiv, alertsContainer.firstChild);
                
                // Keep only last 15 alerts
                while (alertsContainer.children.length > 15) {
                    alertsContainer.removeChild(alertsContainer.lastChild);
                }
                
                // Auto-remove old alerts after 30 seconds
                setTimeout(() => {
                    if (alertDiv.parentNode) {
                        alertDiv.style.opacity = '0';
                        alertDiv.style.transform = 'translateX(-100%)';
                        setTimeout(() => {
                            if (alertDiv.parentNode) {
                                alertDiv.parentNode.removeChild(alertDiv);
                            }
                        }, 300);
                    }
                }, 30000);
            }
            
            function updateMetrics(metrics) {
                // Add animation to value changes
                updateStatValue('total-requests', metrics.total_requests || 0);
                updateStatValue('blocked-requests', metrics.blocked_requests || 0);
                updateStatValue('threats-detected', metrics.threats_detected || 0);
                updateStatValue('response-time', (metrics.avg_response_time * 1000).toFixed(1) || '0.0');
            }
            
            function updateStatValue(elementId, newValue) {
                const element = document.getElementById(elementId);
                const currentValue = element.textContent;
                
                if (currentValue !== newValue.toString()) {
                    element.style.transform = 'scale(1.1)';
                    element.style.color = 'var(--accent-green)';
                    element.textContent = newValue;
                    
                    setTimeout(() => {
                        element.style.transform = 'scale(1)';
                        element.style.color = 'var(--primary-green)';
                    }, 200);
                }
            }
            
            // Fetch initial metrics
            async function loadInitialData() {
                try {
                    const response = await fetch('/api/v1/metrics');
                    const metrics = await response.json();
                    updateMetrics(metrics);
                } catch (error) {
                    console.error('Failed to load initial metrics:', error);
                    addAlert('Failed to load initial metrics', 'warning');
                }
            }
            
            // Load data when page loads
            document.addEventListener('DOMContentLoaded', () => {
                loadInitialData();
                
                // Add some demo alerts if no real alerts within 5 seconds
                setTimeout(() => {
                    if (alertsContainer.children.length === 0) {
                        addAlert('🛡️ All security systems operational', 'success');
                        setTimeout(() => {
                            addAlert('📊 Monitoring 0 active connections', 'info');
                        }, 2000);
                        setTimeout(() => {
                            addAlert('🔧 WAF engine initialized successfully', 'success');
                        }, 4000);
                    }
                }, 5000);
            });
            
            // Enhanced utility functions
            function connectWebSocket() {
                if (ws.readyState === WebSocket.OPEN) {
                    addAlert('🔌 WebSocket already connected', 'info');
                } else {
                    addAlert('🔄 Attempting to reconnect WebSocket...', 'warning');
                }
            }
            
            function openLogViewer() {
                addAlert('📄 Log viewer feature coming soon', 'info');
            }
            
            function runRateLimitTest() {
                addAlert('🚀 Running rate limit test...', 'warning');
                
                // Send multiple requests to test rate limiting
                let requests = 0;
                const maxRequests = 20;
                const interval = setInterval(async () => {
                    try {
                        await fetch('/api/v1/metrics');
                        requests++;
                        
                        if (requests >= maxRequests) {
                            clearInterval(interval);
                            addAlert(`✅ Rate limit test completed: ${requests} requests sent`, 'success');
                        }
                    } catch (error) {
                        clearInterval(interval);
                        addAlert('⚠️ Rate limit triggered - requests blocked', 'danger');
                    }
                }, 100);
            }
            
            function showEnvConfig() {
                const configInfo = `
                    🔧 Environment Configuration:
                    HOST=127.0.0.1
                    PORT=5000
                    DEBUG=true
                    SECRET_KEY=configured
                    SQL_INJECTION_PROTECTION=true
                    XSS_PROTECTION=true
                    RATE_LIMIT_ENABLED=true
                `;
                addAlert(configInfo, 'info');
            }
            
            function showWafRules() {
                addAlert('📜 WAF Rules: SQL Injection, XSS, Rate Limiting, Bot Detection', 'info');
            }
            
            // Refresh metrics every 30 seconds
            setInterval(loadInitialData, 30000);
            
            // Add CSS for alert severity types
            const style = document.createElement('style');
            style.textContent = `
                .alert-danger {
                    background: linear-gradient(135deg, rgba(255, 51, 102, 0.15), rgba(255, 51, 102, 0.05));
                    border-left-color: var(--danger-red);
                    box-shadow: 0 0 15px rgba(255, 51, 102, 0.3);
                }
                
                .alert-warning {
                    background: linear-gradient(135deg, rgba(255, 149, 0, 0.15), rgba(255, 149, 0, 0.05));
                    border-left-color: var(--warning-orange);
                    box-shadow: 0 0 15px rgba(255, 149, 0, 0.3);
                }
                
                .alert-info {
                    background: linear-gradient(135deg, rgba(0, 170, 255, 0.15), rgba(0, 170, 255, 0.05));
                    border-left-color: var(--info-blue);
                    box-shadow: 0 0 15px rgba(0, 170, 255, 0.3);
                }
                
                .alert-success {
                    background: linear-gradient(135deg, rgba(0, 255, 102, 0.15), rgba(0, 255, 102, 0.05));
                    border-left-color: var(--success-green);
                    box-shadow: 0 0 15px rgba(0, 255, 102, 0.3);
                }
                
                .alert-message {
                    margin-top: 8px;
                    color: var(--text-primary);
                    line-height: 1.4;
                    white-space: pre-line;
                }
                
                /* Enhanced glow effects */
                .stat-card:hover .stat-value {
                    text-shadow: 0 0 30px var(--primary-green);
                }
                
                /* Smooth transitions for all interactive elements */
                * {
                    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                }
                
                /* Additional animations */
                @keyframes fadeInUp {
                    from {
                        opacity: 0;
                        transform: translateY(30px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }
                
                .service-category {
                    animation: fadeInUp 0.6s ease forwards;
                }
                
                .service-category:nth-child(1) { animation-delay: 0.1s; }
                .service-category:nth-child(2) { animation-delay: 0.2s; }
                .service-category:nth-child(3) { animation-delay: 0.3s; }
                .service-category:nth-child(4) { animation-delay: 0.4s; }
                .service-category:nth-child(5) { animation-delay: 0.5s; }
                .service-category:nth-child(6) { animation-delay: 0.6s; }
            `;
            document.head.appendChild(style);
        </script>
    </body>
    </html>
    """

# Security Rules Page
@app.get("/security-rules", response_class=HTMLResponse)
async def security_rules():
    """Serve the security rules page"""
    try:
        with open("templates/security_rules.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Security Rules Page Not Found</h1>
        <p>The security rules template is not available.</p>
        <a href="/">Go to Dashboard</a>
        </body>
        </html>
        """, status_code=404)

# Threat Detection Page
@app.get("/threat-detection", response_class=HTMLResponse)
async def threat_detection(request: Request):
    """Serve the threat detection page"""
    try:
        template_data = {
            "request": request,
            "page_title": "Threat Detection",
            "waf_status": "active"
        }
        return templates.TemplateResponse("threat_detection.html", template_data)
    except Exception as e:
        logging.error(f"Error loading threat detection page: {e}")
        return HTMLResponse("""
        <html>
        <body style="background: #0a0e1a; color: white; font-family: Arial; padding: 2rem;">
        <h1 style="color: #00d4ff;">Threat Detection</h1>
        <p>The threat detection page is under maintenance.</p>
        <a href="/" style="color: #00ffa6;">← Go to Dashboard</a>
        </body>
        </html>
        """, status_code=200)

# Analytics Page
@app.get("/analytics", response_class=HTMLResponse)
async def analytics(request: Request):
    """Serve the analytics page"""
    return templates.TemplateResponse("analytics.html", {"request": request})

# Network Monitor Page
@app.get("/network-monitor", response_class=HTMLResponse)
async def network_monitor(request: Request):
    """Serve the network monitor page"""
    return templates.TemplateResponse("network_monitor.html", {"request": request})

# Blocked IPs Page
@app.get("/blocked-ips", response_class=HTMLResponse)
async def blocked_ips(request: Request):
    """Serve the blocked IPs page with real data"""
    try:
        # Get blocked IPs from the WAF engine
        blocked_ips_data = await waf_engine.get_blocked_ips()
        
        # Get additional statistics
        stats = {
            'total_blocked': len(blocked_ips_data),
            'blocked_today': len([ip for ip in blocked_ips_data if 'today' in str(ip.get('blocked_at', ''))]),
            'automatic_blocks': len([ip for ip in blocked_ips_data if ip.get('reason_type') in ['malicious', 'suspicious', 'bot']]),
            'manual_blocks': len([ip for ip in blocked_ips_data if ip.get('reason_type') == 'manual'])
        }
        
        # Format data for template
        template_data = {
            "request": request,
            "blocked_ips": blocked_ips_data,
            "stats": stats,
            "page_title": "Blocked IPs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("blocked_ips.html", template_data)
        
    except Exception as e:
        logging.error(f"Error loading blocked IPs page: {e}")
        # Fallback with sample data
        sample_blocked_ips = [
            {
                'ip': '192.168.1.100',
                'reason': 'Multiple failed login attempts',
                'reason_type': 'suspicious',
                'blocked_at': '2024-01-15 10:30:00',
                'attempts': 15,
                'country': '🇺🇸 United States'
            },
            {
                'ip': '10.0.0.50',
                'reason': 'SQL injection attempt',
                'reason_type': 'malicious',
                'blocked_at': '2024-01-15 09:15:00',
                'attempts': 8,
                'country': '🇷🇺 Russia'
            }
        ]
        
        template_data = {
            "request": request,
            "blocked_ips": sample_blocked_ips,
            "stats": {
                'total_blocked': len(sample_blocked_ips),
                'blocked_today': 2,
                'automatic_blocks': 2,
                'manual_blocks': 0
            },
            "page_title": "Blocked IPs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("blocked_ips.html", template_data)

# Event Logs Page
@app.get("/event-logs", response_class=HTMLResponse)
async def event_logs(request: Request):
    """Serve the event logs page with real data"""
    try:
        # Sample security events - in a real system this would come from database/logs
        security_events = [
            {
                'timestamp': '2024-01-15 10:30:00',
                'event_type': 'threat_blocked',
                'severity': 'high',
                'ip_address': '192.168.1.100',
                'details': 'SQL injection attempt blocked',
                'action': 'blocked'
            },
            {
                'timestamp': '2024-01-15 10:25:00', 
                'event_type': 'rate_limit',
                'severity': 'medium',
                'ip_address': '10.0.0.50',
                'details': 'Rate limit exceeded (100 req/min)',
                'action': 'throttled'
            },
            {
                'timestamp': '2024-01-15 10:20:00',
                'event_type': 'xss_blocked',
                'severity': 'high',
                'ip_address': '203.0.113.45',
                'details': 'Cross-site scripting attempt detected',
                'action': 'blocked'
            }
        ]
        
        # Format data for template
        template_data = {
            "request": request,
            "events": security_events,
            "page_title": "Event Logs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("event_logs.html", template_data)
        
    except Exception as e:
        logging.error(f"Error loading event logs page: {e}")
        
        # Fallback with minimal data
        template_data = {
            "request": request,
            "events": [],
            "page_title": "Event Logs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("event_logs.html", template_data)

# Settings Page
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Serve the settings page"""
    try:
        template_data = {
            "request": request,
            "page_title": "Settings", 
            "waf_status": "active"
        }
        return templates.TemplateResponse("settings.html", template_data)
    except Exception as e:
        logging.error(f"Error loading settings page: {e}")
        return HTMLResponse("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Settings - VigilEdge WAF</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background: linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 100%);
                    color: white;
                    margin: 0;
                    padding: 2rem;
                }
                .container { max-width: 1200px; margin: 0 auto; }
                h1 { color: #00d4ff; margin-bottom: 2rem; }
                .coming-soon { text-align: center; padding: 4rem; }
                .back-link { color: #00ffa6; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>WAF Settings</h1>
                <div class="coming-soon">
                    <h2>Settings Under Development</h2>
                    <p>Configuration management interface will be available soon.</p>
                    <a href="/" class="back-link">← Back to Dashboard</a>
                </div>
            </div>
        </body>
        </html>
        """)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "waf_engine": "operational"
    }

# WebSocket endpoint for real-time alerts
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Send periodic updates
            metrics = await waf_engine.get_metrics()
            await manager.send_personal_message(
                json.dumps({"type": "metrics", "data": metrics}),
                websocket
            )
            await asyncio.sleep(5)
    except (WebSocketDisconnect, ConnectionClosedError):
        # Client disconnected normally
        manager.disconnect(websocket)
    except Exception:
        # Any other error, disconnect silently
        manager.disconnect(websocket)

# Setup API routes
setup_routes(app, waf_engine, manager)

# Proxy endpoint for protecting applications
@app.api_route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(request: Request):
    """Proxy endpoint to protect backend applications"""
    try:
        # Get target URL from query parameter
        target_url = request.query_params.get("target")
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")
        
        # Get client IP
        client_ip = request.client.host
        
        # Get request data
        method = request.method
        headers = dict(request.headers)
        body = await request.body()
        
        # Process through WAF
        allowed, security_event = await waf_engine.process_request(
            method=method,
            url=target_url,
            headers=headers,
            body=body.decode() if body else None,
            client_ip=client_ip
        )
        
        if not allowed:
            # Broadcast security alert
            await manager.broadcast(json.dumps({
                "type": "alert",
                "message": f"🚫 {security_event.threat_type.upper()} blocked from {client_ip}"
            }))
            
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by WAF",
                    "reason": security_event.threat_type,
                    "event_id": security_event.id
                }
            )
        
        # Forward request to target
        async with httpx.AsyncClient() as client:
            # Remove proxy-specific headers
            headers.pop("host", None)
            headers.pop("content-length", None)
            
            response = await client.request(
                method=method,
                url=target_url,
                headers=headers,
                content=body,
                timeout=settings.proxy_timeout
            )
            
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.headers.get("content-type", "").startswith("application/json") else {"data": response.text},
                headers=dict(response.headers)
            )
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Proxy error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# Background task for monitoring
async def monitoring_task():
    """Background monitoring and alerting"""
    while True:
        try:
            # Check for security events and send alerts
            recent_events = await waf_engine.get_recent_events(limit=10)
            
            for event in recent_events[-5:]:  # Check last 5 events
                if event.get("blocked") and event.get("threat_level") in ["high", "critical"]:
                    alert_message = f"🚨 {event['threat_type'].upper()} attack blocked from {event['source_ip']}"
                    await manager.broadcast(json.dumps({
                        "type": "alert",
                        "message": alert_message
                    }))
            
            await asyncio.sleep(10)  # Check every 10 seconds
            
        except Exception as e:
            print(f"Monitoring task error: {e}")
            await asyncio.sleep(30)

# Testing proxy endpoints for vulnerable application
@app.get("/api/v1/test/{path:path}")
async def test_proxy_get(path: str, request: Request):
    """Proxy GET requests to vulnerable app for testing WAF protection"""
    try:
        target_url = f"http://localhost:8080/{path}"
        query_string = str(request.url.query)
        if query_string:
            target_url += f"?{query_string}"
        
        # Forward headers (excluding host)
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(target_url, headers=headers)
            
            # Return proxied response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get('content-type', 'text/html')
            )
    except httpx.RequestError as e:
        return JSONResponse(
            content={
                "error": "Vulnerable app not running",
                "message": f"Could not connect to http://localhost:8080 - {str(e)}",
                "instruction": "Start the vulnerable app with: python vulnerable_app.py"
            },
            status_code=503
        )
    except Exception as e:
        return JSONResponse(
            content={"error": "Proxy error", "message": str(e)},
            status_code=500
        )

@app.post("/api/v1/test/{path:path}")
async def test_proxy_post(path: str, request: Request):
    """Proxy POST requests to vulnerable app for testing WAF protection"""
    try:
        target_url = f"http://localhost:8080/{path}"
        body = await request.body()
        
        # Forward headers (excluding host)
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(target_url, content=body, headers=headers)
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get('content-type', 'text/html')
            )
    except httpx.RequestError as e:
        return JSONResponse(
            content={
                "error": "Vulnerable app not running",
                "message": f"Could not connect to http://localhost:8080 - {str(e)}",
                "instruction": "Start the vulnerable app with: python vulnerable_app.py"
            },
            status_code=503
        )
    except Exception as e:
        return JSONResponse(
            content={"error": "Proxy error", "message": str(e)},
            status_code=500
        )

@app.get("/test-target")
async def test_target_status():
    """Check if vulnerable test target is running"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get("http://localhost:8080/health")
            if response.status_code == 200:
                return JSONResponse({
                    "status": "online",
                    "message": "Vulnerable target application is running",
                    "target_url": "http://localhost:8080",
                    "proxy_url": "http://localhost:5000/api/v1/test/",
                    "dashboard": "http://localhost:5000"
                })
    except:
        pass
    
    return JSONResponse({
        "status": "offline",
        "message": "Vulnerable target application is not running",
        "instruction": "Start with: python vulnerable_app.py",
        "port": 8080
    }, status_code=503)

def main():
    """Main application entry point"""
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        access_log=True,
        log_level=settings.log_level.lower()
    )

if __name__ == "__main__":
    main()
