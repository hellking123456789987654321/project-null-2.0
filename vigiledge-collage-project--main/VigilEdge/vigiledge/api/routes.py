"""
API Routes for VigilEdge WAF
Defines REST API endpoints for managing the WAF
"""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

# Import types (will work once dependencies are installed)
try:
    from fastapi.security import HTTPAuthorizationCredentials
except ImportError:
    HTTPAuthorizationCredentials = None

from ..core.waf_engine import WAFEngine, ThreatLevel, ActionType
from ..core.security_manager import SecurityRule


def setup_routes(app, waf_engine: WAFEngine, websocket_manager):
    """Setup all API routes"""
    
    # Create API router
    api_v1 = APIRouter(prefix="/api/v1", tags=["WAF API"])
    
    @api_v1.get("/metrics")
    async def get_metrics():
        """Get WAF performance metrics"""
        try:
            metrics = await waf_engine.get_metrics()
            return JSONResponse(content=metrics)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/events")
    async def get_recent_events(limit: int = 100):
        """Get recent security events"""
        try:
            events = await waf_engine.get_recent_events(limit=limit)
            return JSONResponse(content={"events": events, "count": len(events)})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/blocked-ips")
    async def get_blocked_ips():
        """Get list of blocked IP addresses"""
        try:
            blocked_ips = await waf_engine.get_blocked_ips()
            return JSONResponse(content={"blocked_ips": blocked_ips, "count": len(blocked_ips)})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/block-ip")
    async def block_ip(request_data: dict):
        """Block an IP address"""
        try:
            ip = request_data.get("ip")
            reason = request_data.get("reason", "Manual block")
            
            if not ip:
                raise HTTPException(status_code=400, detail="IP address is required")
            
            success = await waf_engine.block_ip(ip, reason)
            if success:
                # Send WebSocket notification
                await websocket_manager.broadcast(json.dumps({
                    "type": "alert",
                    "message": f"🚫 IP {ip} has been blocked: {reason}"
                }))
                return JSONResponse(content={"status": "success", "message": f"IP {ip} blocked"})
            else:
                raise HTTPException(status_code=400, detail="Invalid IP address")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/unblock-ip")
    async def unblock_ip(request_data: dict):
        """Unblock an IP address"""
        try:
            ip = request_data.get("ip")
            
            if not ip:
                raise HTTPException(status_code=400, detail="IP address is required")
            
            success = await waf_engine.unblock_ip(ip)
            if success:
                # Send WebSocket notification
                await websocket_manager.broadcast(json.dumps({
                    "type": "alert",
                    "message": f"✅ IP {ip} has been unblocked"
                }))
                return JSONResponse(content={"status": "success", "message": f"IP {ip} unblocked"})
            else:
                raise HTTPException(status_code=404, detail="IP not found in blocklist")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/security/summary")
    async def get_security_summary():
        """Get security configuration summary"""
        try:
            summary = await waf_engine.security_manager.get_security_summary()
            return JSONResponse(content=summary)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/security/rules")
    async def get_security_rules():
        """Get all security rules"""
        try:
            rules = await waf_engine.security_manager.export_rules()
            return JSONResponse(content={"rules": rules, "count": len(rules)})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/security/rules")
    async def create_security_rule(rule_data: dict):
        """Create a new security rule"""
        try:
            rule = SecurityRule(
                id=rule_data.get("id"),
                name=rule_data.get("name"),
                description=rule_data.get("description"),
                pattern=rule_data.get("pattern"),
                threat_type=rule_data.get("threat_type"),
                severity=rule_data.get("severity"),
                enabled=rule_data.get("enabled", True)
            )
            
            success = await waf_engine.security_manager.add_security_rule(rule)
            if success:
                return JSONResponse(content={"status": "success", "message": "Rule created"})
            else:
                raise HTTPException(status_code=400, detail="Invalid rule pattern")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.delete("/security/rules/{rule_id}")
    async def delete_security_rule(rule_id: str):
        """Delete a security rule"""
        try:
            success = await waf_engine.security_manager.remove_security_rule(rule_id)
            if success:
                return JSONResponse(content={"status": "success", "message": "Rule deleted"})
            else:
                raise HTTPException(status_code=404, detail="Rule not found")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.put("/security/rules/{rule_id}/enable")
    async def enable_security_rule(rule_id: str):
        """Enable a security rule"""
        try:
            success = await waf_engine.security_manager.enable_rule(rule_id)
            if success:
                return JSONResponse(content={"status": "success", "message": "Rule enabled"})
            else:
                raise HTTPException(status_code=404, detail="Rule not found")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.put("/security/rules/{rule_id}/disable")
    async def disable_security_rule(rule_id: str):
        """Disable a security rule"""
        try:
            success = await waf_engine.security_manager.disable_rule(rule_id)
            if success:
                return JSONResponse(content={"status": "success", "message": "Rule disabled"})
            else:
                raise HTTPException(status_code=404, detail="Rule not found")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/security/reputation/{ip}")
    async def check_ip_reputation(ip: str):
        """Check IP reputation"""
        try:
            reputation = await waf_engine.security_manager.check_ip_reputation(ip)
            return JSONResponse(content=reputation)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/security/whitelist")
    async def add_to_whitelist(request_data: dict):
        """Add IP to whitelist"""
        try:
            ip = request_data.get("ip")
            if not ip:
                raise HTTPException(status_code=400, detail="IP address is required")
            
            success = await waf_engine.security_manager.add_to_whitelist(ip)
            if success:
                return JSONResponse(content={"status": "success", "message": f"IP {ip} added to whitelist"})
            else:
                raise HTTPException(status_code=400, detail="Invalid IP address")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/security/blacklist") 
    async def add_to_blacklist(request_data: dict):
        """Add IP to blacklist"""
        try:
            ip = request_data.get("ip")
            if not ip:
                raise HTTPException(status_code=400, detail="IP address is required")
            
            success = await waf_engine.security_manager.add_to_blacklist(ip)
            if success:
                # Send WebSocket notification
                await websocket_manager.broadcast(json.dumps({
                    "type": "alert", 
                    "message": f"🚫 IP {ip} added to permanent blacklist"
                }))
                return JSONResponse(content={"status": "success", "message": f"IP {ip} added to blacklist"})
            else:
                raise HTTPException(status_code=400, detail="Invalid IP address")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/admin/reset-metrics")
    async def reset_metrics():
        """Reset WAF metrics"""
        try:
            await waf_engine.reset_metrics()
            return JSONResponse(content={"status": "success", "message": "Metrics reset"})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/admin/clear-events")
    async def clear_events():
        """Clear security events history"""
        try:
            await waf_engine.clear_events()
            return JSONResponse(content={"status": "success", "message": "Events cleared"})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/admin/config")
    async def get_config():
        """Get current WAF configuration"""
        try:
            from ..config import get_settings
            settings = get_settings()
            config = {
                "app_name": settings.app_name,
                "version": settings.app_version,
                "environment": settings.environment,
                "security_features": {
                    "sql_injection_protection": settings.sql_injection_protection,
                    "xss_protection": settings.xss_protection,
                    "ddos_protection": settings.ddos_protection,
                    "ip_blocking_enabled": settings.ip_blocking_enabled,
                    "bot_detection_enabled": settings.bot_detection_enabled,
                    "rate_limit_enabled": settings.rate_limit_enabled,
                },
                "rate_limiting": {
                    "requests": settings.rate_limit_requests,
                    "window": settings.rate_limit_window,
                },
                "monitoring": {
                    "metrics_enabled": settings.metrics_enabled,
                    "health_check_interval": settings.health_check_interval,
                }
            }
            return JSONResponse(content=config)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # Test endpoints for demo purposes
    @api_v1.get("/test/trigger-sql-injection")
    async def test_sql_injection():
        """Test endpoint to trigger SQL injection detection"""
        # This will be caught by the WAF
        test_payload = "' UNION SELECT * FROM users--"
        return JSONResponse(content={"message": "This should be blocked", "payload": test_payload})
    
    @api_v1.get("/test/trigger-xss")
    async def test_xss():
        """Test endpoint to trigger XSS detection"""
        # This will be caught by the WAF
        test_payload = "<script>alert('XSS')</script>"
        return JSONResponse(content={"message": "This should be blocked", "payload": test_payload})
    
    # Include API router in the main app
    app.include_router(api_v1)
