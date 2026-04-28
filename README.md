# OOBserver-Next

**内网 OOB (Out-of-Band) 漏洞利用平台** — 攻击侧工具，非靶机。

生成利用链 Payload + 接收多协议回调 + 内存马投递 + 自建 C2 管道。**完全离线运行，无需外网依赖。**

---

## 架构

```
浏览器 ──► Vue3 前端 :3000
              │
              ▼ REST / WebSocket
        FastAPI 后端 :8010
        ├── LDAP 监听 :1389
        ├── RMI  监听 :1099
        ├── TCP  收包 :9999
        └── DNS  监听 :5353 (可选)
              │ HTTP 代理
              ▼
        Sidecar (Spring Boot) :8711         ← 82 条 Payload 链
        └── java-chains (内嵌) :8011        ← 48 条增强链
```

| 组件 | 技术栈 | 端口 |
|---|---|---|
| Frontend | Vue 3 + Ant Design Vue + Vite | 3000 |
| Backend | FastAPI (Python 3.11) | 8010 |
| Sidecar | Spring Boot 3 (Java 17) | 8711 |
| java-chains | Spring Boot (内嵌) | 8011 (容器内) |

---

## 快速部署（Docker Compose）

**前提：** 已安装 Docker Compose v2

```bash
git clone http://110.42.41.92:3333/lyq/oobserver-next.git
cd oobserver-next

# 必填：服务器 IP（目标机器必须能访问此 IP）和 JWT 密钥
export OOBX_PUBLIC_ADDRESS=10.0.7.25
export OOBX_JWT_SECRET=$(openssl rand -hex 32)

# 首次构建约 3-5 分钟
docker compose up -d

# 确认三个服务均健康
docker compose ps
```

访问 `http://<服务器IP>:3000`，默认账号 `admin / admin123`，**首次登录后请立即修改密码**。

> **本机 5353 端口冲突？** 设置 `OOBX_DNS_PORT=5354` 再启动。

---

## 支持的 Payload 链（共 82 条）

### Java 原生反序列化（ysoserial）
`ysoserial_cc1` ~ `cc7` · `ysoserial_cb1` · `cb_no_cc` · `ysoserial_spring1/2` · `ysoserial_hibernate1` · `ysoserial_rome` · `ysoserial_groovy1` · `ysoserial_jdk7u21` · `ysoserial_urldns` · `ysoserial_jrmp_client/listener`

### Hessian 协议（marshalsec）
`hessian1_cc6` · `hessian1_spring` · `hessian1_rome` · `hessian2_cc6` · `hessian2_spring` · `hessian2_rome`

### Fastjson / XStream / Shiro / C3P0
`fastjson_jdbcrowset` · `fastjson_jdbcrowset_v2` · `fastjson_bcel` · `xstream_eventhandler` · `xstream_imageio` · `shiro_cbc` · `shiro_gcm` · `c3p0_jndi` · `c3p0_wrapperds`

### java-chains 增强链（`jchains_*`，48 条）

**Hessian1（8）**: `jchains_hessian1_spring` · `jchains_hessian1_spring2` · `jchains_hessian1_spring_exec` · `jchains_hessian1_exec` · `jchains_hessian1_bcel` · `jchains_hessian1_rome1` · `jchains_hessian1_rome2` · `jchains_hessian1_secondary`

**Hessian2（10）**: `jchains_hessian2_spring` · `jchains_hessian2_spring2` · `jchains_hessian2_spring_exec` · `jchains_hessian2_exec` · `jchains_hessian2_bcel` · `jchains_hessian2_rome1` · `jchains_hessian2_rome2` · `jchains_hessian2_secondary` · `jchains_hessian2_tostring_xbean` · `jchains_hessian2_tostring_jackson`

**Fastjson（4）**: `jchains_fastjson` / `jchains_fastjson_jndi` · `jchains_fastjson_bcel` · `jchains_fastjson_c3p0_h2`

**XStream（3）**: `jchains_xstream` / `jchains_xstream_jndi` · `jchains_xstream_exec`

**Java 反序列化（14）**: `jchains_cc1` ~ `jchains_cc4` · `jchains_cc6` / `jchains_native_cc6` · `jchains_cb1` / `jchains_native_cb1` · `jchains_native_cb2` · `jchains_native_cb1_jndi` · `jchains_native_jackson` · `jchains_native_jdk17_1` · `jchains_native_jdk17_2` · `jchains_native_c3p0_el` · `jchains_native_c3p0_ldap` · `jchains_native_k1_secondary`

**JNDI ResourceRef（4）**: `jchains_jndi_tomcat_el` · `jchains_jndi_groovy` · `jchains_jndi_snakeyaml` · `jchains_jndi_beanshell`

**其他（3）**: `jchains_shiro_cbc` · `jchains_h2_jdbc` · `jchains_blazeds_axis2`

### OOB 检测 / JNDI 触发（纯 Python）
`jndi_ldap_basic` · `jndi_rmi_basic` · `exfil_log4j` · `exfil_fastjson` · `exfil_snakeyaml` · `exfil_xstream` · `blind_*` 等

---

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `OOBX_PUBLIC_ADDRESS` | **必填** | 目标可达的服务器 IP |
| `OOBX_JWT_SECRET` | **必填** | JWT 签名密钥，生产环境用随机值 |
| `OOBX_HTTP_PORT` | `8010` | Backend + 回调端口 |
| `OOBX_LDAP_PORT` | `1389` | LDAP 监听端口 |
| `OOBX_RMI_PORT` | `1099` | RMI 监听端口 |
| `OOBX_TCP_PORT` | `9999` | TCP 收包端口 |
| `OOBX_DNS_PORT` | `5353` | DNS 监听端口（UDP） |
| `OOBX_DNS_ENABLED` | `false` | 是否启用 DNS 监听 |
| `OOBX_DNS_ZONE` | `oob.local` | 权威 DNS 域名 |
| `OOBX_UI_PORT` | `3000` | 前端访问端口 |
| `OOBX_DATABASE_URL` | SQLite（内置） | 支持 PostgreSQL |
| `OOBX_SIDECAR_URL` | `http://sidecar:8711` | Sidecar 地址 |
| `JAVACHAINS_URL` | `http://127.0.0.1:8011` | java-chains 地址（Sidecar 内部） |

详见 [用户手册](docs/user-manual.md)。
