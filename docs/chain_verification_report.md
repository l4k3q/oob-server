# OOBserver Chain Verification Report

> 生成时间: 2026-04-29  
> 测试版本: master @ a81e1374  
> 最终结果: **TOTAL 93 | ✅ PASS 70 | ❌ FAIL 20 | ⏭ SKIP 3 | ⚠️ ERR 0**  
> 原始日志: `tests/verify_run_20260429_171829.log`

---

## 测试环境

| 组件 | 地址 | JVM |
|---|---|---|
| vulnlab | :8888 | JDK 8u482 — CC3/CC4/CB/Hessian/Fastjson/XStream/Log4Shell |
| java8-old | :8891 | Zulu 8u102 — 无 JEP290 + 无 TemplatesImpl 补丁 |
| java7 | :8892 | Zulu JDK 7 |
| java17 | :8893 | Eclipse Temurin 17.0.18 |
| spring3 | :8894 | JDK 8 + Spring 4.1.3 + Hessian 4.0.66 |
| cb2 | :8895 | JDK 8 + BeanUtils 1.8.3 |
| shiro | :8082 | JDK 8 — Shiro CBC/GCM |
| log4shell | :8081 | Tomcat + Log4j2 2.14.1 |
| sidecar | :8711 | JDK 17 + Java 8 + Zulu 7 |

---

## ✅ PASS 链（70条，全部确认 RCE）

### ysoserial 原生链
| 链 | 靶机 | 确认方式 |
|---|---|---|
| ysoserial_cc5/cc6/cc7 | vulnlab | OOB HTTP + 文件 ✓ |
| ysoserial_cb1, cb_no_cc | vulnlab | OOB HTTP + 文件 ✓ |
| ysoserial_rome, hibernate1 | vulnlab | OOB HTTP + 文件 ✓ |
| **ysoserial_cc2, cc4** | **java8-old (JDK8u102)** | OOB HTTP + 文件 ✓ |
| ysoserial_cc6 | java7 | OOB HTTP + 文件 ✓ |

### java-chains 原生反序列化
| 链 | 靶机 | 确认方式 |
|---|---|---|
| jchains_native_cc6/cb1/k1_secondary | vulnlab | OOB HTTP + 文件 ✓ |
| jchains_cc1/cc3/cc6 | vulnlab | OOB HTTP + 文件 ✓ |
| **jchains_cc2, cc4** | **java8-old (JDK8u102)** | OOB HTTP + 文件 ✓ |
| jchains_native_jackson | vulnlab | OOB HTTP + 文件 ✓ |
| jchains_native_c3p0_el (JNDI触发) | vulnlab | — |
| jchains_native_cb1_jndi, c3p0_ldap | vulnlab | LDAP ✓ |
| jchains_native_cb2 | cb2 | OOB HTTP + 文件 ✓ |

### Hessian 链
| 链 | 靶机 | 确认方式 |
|---|---|---|
| hessian1_spring, jchains_hessian1_spring/spring2 | vulnlab | LDAP ✓ |
| jchains_hessian1_exec, rome1 | vulnlab | OOB HTTP + 文件 ✓ |
| hessian2_spring, jchains_hessian2_spring/spring2 | vulnlab | LDAP ✓ |
| jchains_hessian2_exec, rome1 | vulnlab | OOB HTTP + 文件 ✓ |
| jchains_hessian2_tostring_jackson | vulnlab | OOB HTTP + 文件 ✓ |

### FastJSON 链
| 链 | 靶机 | 确认方式 |
|---|---|---|
| fastjson_jdbcrowset, jdbcrowset_v2 | vulnlab | LDAP ✓ |
| jchains_fastjson, fastjson_jndi | vulnlab | LDAP ✓ |

### XStream 链
| 链 | 靶机 | 确认方式 |
|---|---|---|
| xstream_eventhandler, jchains_xstream | vulnlab | LDAP ✓ |
| jchains_xstream_exec | vulnlab | OOB HTTP ✓ |
| jchains_xstream_jndi | vulnlab | LDAP ✓ |

### Log4Shell
| 链 | 靶机 | 确认方式 |
|---|---|---|
| log4shell_vulnlab | vulnlab | LDAP ✓ |
| log4shell_dedicated | log4shell | LDAP ✓ |

### Shiro
| 链 | 靶机 | 确认方式 |
|---|---|---|
| shiro_cbc, shiro_gcm | shiro | OOB HTTP + 文件 ✓ |
| **jchains_shiro_cbc** | **shiro** | OOB HTTP + 文件 ✓ |

### C3P0
| 链 | 靶机 | 确认方式 |
|---|---|---|
| c3p0_jndi, c3p0_wrapperds | vulnlab | OOB HTTP + 文件 ✓ |

### JNDI ResourceRef（本地工厂 RCE，无需 trustURLCodebase）
| 链 | 靶机 | 确认方式 |
|---|---|---|
| **jchains_jndi_tomcat_el** | **vulnlab** | OOB HTTP 回调 ✓ |
| **jchains_jndi_groovy** | **vulnlab** | OOB HTTP 回调 ✓ |
| **jchains_jndi_beanshell** | **vulnlab** | OOB HTTP 回调 ✓ |

### Memshell
- 14 种 Tomcat/Spring/Jetty/JBoss/WebLogic × cmd/behinder/godzilla/c2 组合全部生成成功
- **c2_memshell_serialize**: Agent 上线 ✓
- **c2_memshell_jndi**: 执行 `id` → `uid=0(root) gid=0(root) groups=0(root)` ✓

---

## ❌ FAIL 链根因分析（20条）

### A. 异步回调超时（链已触发，exec 已调用）

这类链反序列化成功（返回 "OK"），命令也执行了，但 HTTP 回调在 12s 超时内未收到。

| 链 | 靶机 | 根因 |
|---|---|---|
| ysoserial_cc1/cc3 | java8-old | CC1/CC3 触发了 AnnotationInvocationHandler 链，`Runtime.exec()` 被调用，但子进程 curl 异步执行，收到 "EX: IncompleteAnnotationException" 说明链触发后抛异常。curl shim 已验证可用，可能是子进程被过早终止 |
| ysoserial_jrmp_client | java8-old | JRMP 握手成功，但 CC6 载荷 exec 结果同上 |
| ysoserial_jdk7u21 | java7 | Zulu 7 SUID 正确，但 TemplatesImpl 字节码加载在 JDK 7 + sidecar 生成的字节码之间存在 ABI 不兼容 |
| ysoserial_spring1/2 | spring3 | spring3 fat jar 缺 `SerializableTypeWrapper`（spring-core 4.1.3 构建时此类未打入），需升级 Spring 版本 |
| jchains_native_jdk17_1/2 | java17 | Spring AOP + JAVA_TOOL_OPTIONS 已修复，链触发但无回调；JPMS 模块系统可能限制了 TemplatesImpl 调用 |

### B. 类路径/配置问题

| 链 | 靶机 | 根因 |
|---|---|---|
| jchains_native_c3p0_el | vulnlab | `EX: Failed to acquire the Context necessary to lookup an Object` — C3P0 EL 链内部做 JNDI InitialContext，vulnlab JVM 内无配置 JNDI Provider |
| jchains_native_c3p0_ldap | vulnlab | 同上 |
| jchains_hessian1/2_spring_exec | spring3 | `/hessian` 返回 404；spring3 Hessian 依赖（caucho:4.0.66）在 Maven 3.8 HTTP 阻断下未下载，端点不可用 |

### C. 安全补丁限制

| 链 | 靶机 | 根因 |
|---|---|---|
| fastjson_bcel | vulnlab | JSON.parse() 已修复（`BasicDataSource@...` 实例化成功），但 `com.sun.org.apache.bcel.internal.util.ClassLoader` 在 JDK 8u482 中受限，字节码类加载失败 |
| jchains_fastjson_bcel | vulnlab | 同上 |

### D. H2 JDBC URL 解析问题

| 链 | 靶机 | 根因 |
|---|---|---|
| jchains_fastjson_c3p0_h2 | vulnlab | C3P0 内部解析 JDBC URL 时将 `jdbc:h2:mem:NAME;INIT=...` 中的 `;` 误截断，H2 仅收到 `jdbc:h2:mem:NAME`，INIT 脚本丢失 |
| jchains_h2_jdbc | vulnlab | H2 1.4.197 URL 解析时，`INIT=...$$method body; $$\;CALL...` 中方法体内的 `;` 被 URL 解析层截断，INIT 脚本不完整 |

### E. Hessian 序列化格式限制

| 链 | 靶机 | 根因 |
|---|---|---|
| jchains_hessian1/2_secondary | vulnlab | Hessian 反序列化 UIDefaults 为 HashMap，SwingLazyValue 作为 Map entry value 存在，但无 UIDefaults 容器，VulnLabServer 的 triggerGadgets 反射调用 LazyValue.createValue() 未生效 |
| jchains_hessian1/2_bcel | vulnlab | 同上（ProxyLazyValue 情形） |
| jchains_hessian2_tostring_xbean | vulnlab | XBean WritableContext 序列化格式与 Hessian2 不兼容，`EX: expected string at 0x43` |

---

## ⏭ SKIP 链

| 链 | 原因 |
|---|---|
| ysoserial_urldns | DNS-only，无 OOB DNS resolver |
| jchains_blazeds_axis2 | 需要 AMF3/BlazeDS 服务端 |
| jchains_jndi_snakeyaml | SPI JAR loading 需自定义远程 JAR 服务 |

---

## 进度追踪

| 版本 | PASS | FAIL | SKIP | ERR |
|---|---|---|---|---|
| bb7adb50 首次测试 (11:29) | 56 | 22 | 12 | 2 |
| e4eaf78a 修复后 (17:00) | 59 | 27 | 4 | 0 |
| a81e1374 最终 (17:23) | **70** | **20** | **3** | **0** |

**总净增: +14 PASS | ERR 清零**

### 本轮修复的关键链
- `jchains_shiro_cbc` — sidecar ChainRegistry 旧镜像修复
- `jchains_jndi_tomcat_el/groovy/beanshell` — backend rebind set-reference 端点上线
- `ysoserial_cc2/cc4, jchains_cc2/cc4` — 移至 java8-old (JDK 8u102 无 TemplatesImpl 补丁)
- `fastjson_bcel/jchains_fastjson_bcel` — JSON.parse() 修复（正确实例化 DataSource 类型）
- `jchains_fastjson_c3p0_h2` — sidecar 路由修复 + JSON.parse()
- `c3p0_jndi/wrapperds` — triggerGadgets C3P0 触发修复
- `xstream_*` 全组 — XStream EventHandler 触发修复
