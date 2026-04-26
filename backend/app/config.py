from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="OOBX_", extra="ignore")

    app_name: str = "oobserver-next"
    debug: bool = False

    # Broker
    broker_host: str = "0.0.0.0"
    broker_port: int = 8010

    # Address handed back in callback URLs (must be reachable from target)
    public_address: str = "127.0.0.1"

    # Listener ports
    http_port: int = 8010  # same process as broker
    ldap_port: int = 1389
    rmi_port: int = 1099
    tcp_port: int = 9999
    dns_port: int = 5353
    dns_enabled: bool = False
    dns_zone: str = "oob.local"

    # Bytecode sidecar
    sidecar_url: str = "http://127.0.0.1:8711"
    sidecar_timeout: float = 10.0

    # DB
    database_url: str = "sqlite+aiosqlite:///./data/oobx.db"

    # Auth
    jwt_secret: str = "change-me-in-prod"
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 60 * 24

    # Security
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])
    ip_whitelist: List[str] = Field(default_factory=list)

    @property
    def http_base(self) -> str:
        scheme = "http"
        return f"{scheme}://{self.public_address}:{self.http_port}"

    @property
    def ldap_base(self) -> str:
        return f"ldap://{self.public_address}:{self.ldap_port}"

    @property
    def rmi_base(self) -> str:
        return f"rmi://{self.public_address}:{self.rmi_port}"

    @property
    def tcp_base(self) -> str:
        return f"tcp://{self.public_address}:{self.tcp_port}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
