from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .auth.router import router as auth_router
from .c2.router import router as c2_router
from .collector.ws import router as ws_router
from .config import get_settings
from .db import init_db
from .events_router import router as events_router
from .listeners.http_collector import router as cb_router
from .listeners.manager import start_all, stop_all
from .compile_router import router as compile_router
from .jrmp_router import router as jrmp_router
from .memshells.router import router as memshell_router
from .payloads.router import router as payload_router
from .projects.router import router as project_router
from .rebind.router import router as rebind_router
from .tokens.router import router as token_router
from .system_router import router as system_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)


async def _ensure_default_admin() -> None:
    """Create default admin on first boot if no users exist."""
    import secrets
    from sqlalchemy import func, select

    from .db import session_scope
    from .models import User
    from .security import hash_password

    async with session_scope() as session:
        total = await session.scalar(select(func.count(User.id)))
        if total == 0:
            admin = User(
                username="admin",
                password_hash=hash_password("admin123"),
                api_key=secrets.token_urlsafe(32),
                is_admin=True,
            )
            session.add(admin)
            await session.commit()
            log.info("Default admin created: admin / admin123  (change password after login)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await _ensure_default_admin()
    await start_all()
    log.info("OOBserver-next started")
    yield
    await stop_all()
    log.info("OOBserver-next stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="OOBserver-next",
        version="0.1.0",
        description="""
## OOB 利用平台 — 内网 / 隔离网环境专用

**不是验证平台，是利用平台。** 不依赖外部 DNS/dnslog，所有监听器本地运行。

### 核心能力

| 模块 | 说明 |
|------|------|
| 多协议回连 | HTTP / LDAP / RMI / TCP / DNS（权威服务器） |
| Payload 工厂 | 50+ 利用链（ysoserial CC/CB/Spring/ROME/Groovy...）|
| JNDI 重绑定 | LDAP referral → sidecar 字节码 → 目标 JVM 加载 |
| 内存马生成 | Tomcat/Spring/Jetty/JBoss/WebLogic × cmd/冰蝎/哥斯拉 |
| 盲打/不出网 | 时间盲注 / ICMP / HTTP 内网 / SMB / DNS 内网 |
| Agent C2 | 内存马上线后轻量指令通道 |

### 认证方式

所有 `/api/*` 接口需要认证，支持两种方式：
- **Bearer Token**：`Authorization: Bearer <token>`（登录后获取）
- **API Key**：`X-API-Key: <key>`（在个人设置中获取）

### 快速开始

1. `POST /api/auth/register` 注册账号（首个用户自动成为管理员）
2. `POST /api/auth/login` 登录获取 Token
3. `POST /api/projects` 创建项目
4. `POST /api/tokens` 申请 OOB Token（选择 intent = record/jndi/memshell）
5. `GET /api/tokens/{token}/events` 查询命中记录
""",
        openapi_tags=[
            {"name": "auth",       "description": "认证：注册 / 登录 / API Key 管理"},
            {"name": "projects",   "description": "项目管理：按目标或任务分组 Token"},
            {"name": "tokens",     "description": "OOB Token：多协议回连地址、意图配置"},
            {"name": "payloads",   "description": "Payload 工厂：50+ 利用链生成（CC/CB/JNDI/Log4j/Shiro/盲打等）"},
            {"name": "memshells",  "description": "内存马工坊：Tomcat/Spring/Jetty/JBoss/WebLogic × cmd/冰蝎/哥斯拉"},
            {"name": "rebind",     "description": "LDAP/RMI 重绑定：为 Token 注册字节码，控制 LDAP 返回内容"},
            {"name": "events",     "description": "回连事件：全局事件查询 + Intent 影响说明"},
            {"name": "c2",         "description": "Agent C2：内存马上线注册 / 指令下发 / 结果回收"},
            {"name": "callback",   "description": "回调端点：HTTP 回连接收（不需要认证，目标直接访问）"},
        ],
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(auth_router)
    app.include_router(project_router)
    app.include_router(token_router)
    app.include_router(payload_router)
    app.include_router(compile_router)
    app.include_router(jrmp_router)
    app.include_router(memshell_router)
    app.include_router(rebind_router)
    app.include_router(c2_router)
    app.include_router(cb_router)
    app.include_router(ws_router)
    app.include_router(events_router)
    app.include_router(system_router)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": "0.1.0"}

    # Serve built frontend LAST so API routes take precedence
    frontend_dist = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
    frontend_index = os.path.join(frontend_dist, "index.html")

    if os.path.isdir(frontend_dist):
        # Mount static assets (JS/CSS/img) under /assets so they resolve correctly
        assets_dir = os.path.join(frontend_dist, "assets")
        if os.path.isdir(assets_dir):
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        # SPA fallback: any path not matched by API routes returns index.html
        # This allows Vue Router to handle client-side routing (/dashboard, /tokens, etc.)
        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(request: Request, full_path: str) -> FileResponse:
            # Try serving the exact file first (favicon.ico, robots.txt, etc.)
            candidate = os.path.join(frontend_dist, full_path)
            if os.path.isfile(candidate):
                return FileResponse(candidate)
            # All other paths → index.html (Vue Router handles the route)
            return FileResponse(frontend_index)
    else:
        # Frontend not built yet — return helpful message
        @app.get("/{full_path:path}", include_in_schema=False)
        async def frontend_not_built(request: Request, full_path: str) -> JSONResponse:
            return JSONResponse(
                {"detail": "Frontend not built. Run: cd frontend && npm install && npm run build"},
                status_code=503,
            )

    return app


app = create_app()
