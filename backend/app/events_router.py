from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth.deps import current_user
from .db import get_session
from .models import Event, User
from .schemas import EventOut

router = APIRouter(prefix="/api/events", tags=["events"])

INTENT_GUIDE = {
    "record": {
        "description": "仅记录回连，LDAP/RMI 不返回字节码",
        "ldap_behavior": "返回 searchResDone(success)，无 JavaNamingReference",
        "use_when": "验证目标是否能触达 OOBserver，不需要 RCE",
    },
    "jndi": {
        "description": "LDAP 重绑定模式：返回 JavaNamingReference 指向 sidecar class 端点",
        "ldap_behavior": "返回 javaClassName + javaCodeBase + javaFactory attrs → 目标 JVM 拉取并加载字节码",
        "rmi_behavior": "RMI listener only records connections; RMI rebind/JRMP referral is not implemented",
        "use_when": "JNDI 注入漏洞（Log4Shell/FastJson/JNDI EL 等），目标 JDK ≤ 8u191 或高版本绕过",
        "prerequisite": "必须先调用 POST /api/rebind/{token}/set 或通过 Memshell Lab 生成字节码并注册",
    },
    "memshell": {
        "description": "同 jndi，但意图明确为投递内存马字节码",
        "ldap_behavior": "同 jndi",
        "use_when": "通过 JNDI/反序列化向目标注入内存马（Tomcat Filter/Spring Interceptor 等）",
        "prerequisite": "需先在 Memshell Lab 生成 .class 并通过 /api/rebind/{token}/set 注册到 sidecar",
    },
    "serialize": {
        "description": "LDAP 返回 javaSerializedData attr，目标 JVM 直接反序列化",
        "ldap_behavior": "返回含序列化字节的 javaSerializedData — 任意 JDK 版本可用（无 codebase 限制）",
        "use_when": "高版本 JDK 绕过：目标 JDK ≥ 8u191 但有可序列化 gadget 库（CC/CB 等）",
        "prerequisite": "需先通过 Payload Builder 生成序列化字节并注册到 sidecar",
    },
}


@router.get("/intent-guide")
async def intent_guide(_user: User = Depends(current_user)) -> dict:
    """
    解释 token intent 字段对 LDAP/RMI 监听器行为的影响。

    **intent 决定 LDAP 搜索响应内容**：
    - `record`  → 只记录，不返回字节码
    - `jndi`    → 返回 JavaNamingReference，目标 JVM 远程加载 class
    - `memshell`→ 同 jndi，明确语义为内存马投递
    - `serialize` → 返回 javaSerializedData，目标直接反序列化（高版本 JDK 绕过）

    **完整利用流程**：
    1. 创建 token（intent=jndi/memshell/serialize）
    2. 在 Memshell Lab 或 Payload Builder 生成字节码
    3. 调用 POST /api/rebind/{token}/set 注册字节码到 sidecar
    4. 将 ldap_url 注入目标漏洞点
    5. 目标回连 → LDAP 返回 reference → sidecar 提供 .class → 目标加载执行
    """
    return {"intents": INTENT_GUIDE}


@router.get("", response_model=list[EventOut])
async def list_events(
    limit: int = Query(500, le=2000),
    protocol: str | None = None,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[Event]:
    """全局事件列表（不限 token）"""
    q = select(Event).order_by(Event.id.desc()).limit(limit)
    if protocol:
        q = q.where(Event.protocol == protocol)
    res = await session.execute(q)
    return list(res.scalars())
