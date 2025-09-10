"""
Configuration management for VigilEdge WAF
Handles environment variables and application settings
"""

import os
from typing import Optional, List
from pydantic import Field, validator
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with validation"""
    
    # Application Configuration
    app_name: str = Field(default="VigilEdge WAF", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    debug: bool = Field(default=False, env="DEBUG")
    host: str = Field(default="127.0.0.1", env="HOST")
    port: int = Field(default=5000, env="PORT")
    environment: str = Field(default="development", env="ENVIRONMENT")
    
    # Security Configuration
    secret_key: str = Field(default="vigiledge-change-me", env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    admin_username: str = Field(default="admin", env="ADMIN_USERNAME")
    admin_password: str = Field(default="admin", env="ADMIN_PASSWORD")
    
    # Database Configuration
    database_url: str = Field(default="sqlite:///./vigiledge.db", env="DATABASE_URL")
    database_echo: bool = Field(default=False, env="DATABASE_ECHO")
    
    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    redis_expire_time: int = Field(default=3600, env="REDIS_EXPIRE_TIME")
    
    # Rate Limiting Configuration
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=60, env="RATE_LIMIT_WINDOW")
    rate_limit_enabled: bool = Field(default=True, env="RATE_LIMIT_ENABLED")
    
    # WAF Security Settings
    sql_injection_protection: bool = Field(default=True, env="SQL_INJECTION_PROTECTION")
    xss_protection: bool = Field(default=True, env="XSS_PROTECTION")
    ddos_protection: bool = Field(default=True, env="DDOS_PROTECTION")
    ip_blocking_enabled: bool = Field(default=True, env="IP_BLOCKING_ENABLED")
    bot_detection_enabled: bool = Field(default=True, env="BOT_DETECTION_ENABLED")
    
    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: str = Field(default="logs/vigiledge.log", env="LOG_FILE")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    
    # GeoIP Configuration
    geoip_enabled: bool = Field(default=False, env="GEOIP_ENABLED")
    geoip_db_path: str = Field(default="./data/GeoLite2-City.mmdb", env="GEOIP_DB_PATH")
    
    # Monitoring Configuration
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    prometheus_port: int = Field(default=9090, env="PROMETHEUS_PORT")
    health_check_interval: int = Field(default=30, env="HEALTH_CHECK_INTERVAL")
    
    # Alert Configuration
    webhook_alerts_enabled: bool = Field(default=False, env="WEBHOOK_ALERTS_ENABLED")
    webhook_url: Optional[str] = Field(default=None, env="WEBHOOK_URL")
    email_alerts_enabled: bool = Field(default=False, env="EMAIL_ALERTS_ENABLED")
    alert_email: Optional[str] = Field(default=None, env="ALERT_EMAIL")
    
    # Proxy Configuration
    proxy_timeout: int = Field(default=30, env="PROXY_TIMEOUT")
    max_proxy_retries: int = Field(default=3, env="MAX_PROXY_RETRIES")
    proxy_buffer_size: int = Field(default=65536, env="PROXY_BUFFER_SIZE")
    
    @validator("secret_key")
    def validate_secret_key(cls, v):
        if v == "vigiledge-change-me" and os.getenv("ENVIRONMENT") == "production":
            raise ValueError("Secret key must be changed in production")
        return v
    
    @validator("log_level")
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()
    
    @validator("environment")
    def validate_environment(cls, v):
        valid_envs = ["development", "staging", "production"]
        if v not in valid_envs:
            raise ValueError(f"Environment must be one of {valid_envs}")
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings"""
    return Settings()


def get_database_url() -> str:
    """Get database URL with proper formatting"""
    settings = get_settings()
    return settings.database_url


def is_production() -> bool:
    """Check if running in production environment"""
    settings = get_settings()
    return settings.environment == "production"


def is_debug_mode() -> bool:
    """Check if debug mode is enabled"""
    settings = get_settings()
    return settings.debug


# Security configuration helpers
def get_security_config() -> dict:
    """Get all security-related configuration"""
    settings = get_settings()
    return {
        "sql_injection_protection": settings.sql_injection_protection,
        "xss_protection": settings.xss_protection,
        "ddos_protection": settings.ddos_protection,
        "ip_blocking_enabled": settings.ip_blocking_enabled,
        "bot_detection_enabled": settings.bot_detection_enabled,
        "rate_limit_enabled": settings.rate_limit_enabled,
        "rate_limit_requests": settings.rate_limit_requests,
        "rate_limit_window": settings.rate_limit_window,
    }


def get_logging_config() -> dict:
    """Get logging configuration"""
    settings = get_settings()
    return {
        "level": settings.log_level,
        "file": settings.log_file,
        "format": settings.log_format,
    }
