# Chain Test Checklist — OOBserver RCE Verification

> 生成时间: 2026-04-29  
> 要求: 每条链必须确认 **真实 RCE**（文件落地或 OOB HTTP 回调），不接受仅 LDAP 回连

---

## 当前状态总览（2026-04-29 11:29 run）

```
TOTAL 92 | ✅ PASS 56 | ❌ FAIL 22 | ⏭ SKIP 12 | ⚠️ ERR 2
```

---

## 📋 各链测试清单

### Section 1: ysoserial 原生链

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| ysoserial_cc2 | vulnlab :8888 | ❌ ClassNotFoundException CC4 | sidecar 重建(ChainRegistry fix) | ✅ |
| ysoserial_cc4 | vulnlab :8888 | ❌ ClassNotFoundException CC4 | sidecar 重建 | ✅ |
| ysoserial_cc5 | vulnlab :8888 | ✅ PASS | — | ✅ |
| ysoserial_cc6 | vulnlab :8888 | ✅ PASS | — | ✅ |
| ysoserial_cc7 | vulnlab :8888 | ✅ PASS | — | ✅ |
| ysoserial_cb1 | vulnlab :8888 | ✅ PASS | — | ✅ |
| cb_no_cc | vulnlab :8888 | ✅ PASS | — | ✅ |
| ysoserial_rome | vulnlab :8888 | ✅ PASS | — | ✅ |
| ysoserial_hibernate1 | vulnlab :8888 | ✅ PASS | — | ✅ |
| **ysoserial_groovy1** | **java8-old :8891** | ❌ SUID mismatch JDK17 | 移至 JDK8 target + groovy dep | ✅ |
| ysoserial_cc1 | java8-old :8891 | ❌ no callback (curl broken) | busybox curl shim | ✅ |
| ysoserial_cc3 | java8-old :8891 | ❌ no callback (curl broken) | busybox curl shim | ✅ |
| ysoserial_jdk7u21 | java7 :8892 | ❌ no callback (Zulu7 missing) | robust Zulu7 path detect | ✅ |
| ysoserial_spring1 | spring3 :8894 | ❌ ClassNotFoundException Spring | pom-cc3 + force rebuild | ✅ |
| ysoserial_spring2 | spring3 :8894 | ❌ ClassNotFoundException Spring | pom-cc3 + force rebuild | ✅ |
| ysoserial_urldns | — | ⏭ DNS-only | DNS 未配置，保持 SKIP | ⏭ |
| ysoserial_jrmp_client | java8-old :8891 | ❌ no callback (curl broken) | busybox curl shim | ✅ |

### Section 2: java-chains 原生反序列化

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| jchains_native_cc6 | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_native_cb1 | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_native_k1_secondary | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_cc1 | vulnlab :8888 | ✅ PASS | — | ✅ |
| **jchains_cc2** | vulnlab :8888 | ❌ ClassNotFoundException CC4 | sidecar 重建 | ✅ |
| jchains_cc3 | vulnlab :8888 | ✅ PASS | — | ✅ |
| **jchains_cc4** | vulnlab :8888 | ❌ ClassNotFoundException CC4 | sidecar 重建 | ✅ |
| jchains_cc6 | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_native_jackson | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_native_c3p0_el | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_native_cb1_jndi | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_native_c3p0_ldap | vulnlab :8888 | ✅ PASS | — | ✅ |
| **jchains_native_jdk17_1** | java17 :8893 | ❌ ClassNotFoundException SpringAOP | pom-jdk17 Spring AOP | ✅ |
| **jchains_native_jdk17_2** | java17 :8893 | ❌ ClassNotFoundException SpringAOP | pom-jdk17 Spring AOP | ✅ |
| jchains_native_cb2 | cb2 :8895 | ✅ PASS | — | ✅ |

### Section 3: Hessian1 链

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| hessian1_spring | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian1_spring | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian1_spring2 | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian1_exec | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian1_rome1 | vulnlab :8888 | ✅ PASS | — | ✅ |
| **jchains_hessian1_rome2** | vulnlab :8888 | ❌ no callback | triggerGadgets 已有 SignedObject | 🔍 |
| **jchains_hessian1_secondary** | vulnlab :8888 | ❌ SwingLazyValue no trigger | LazyValue.createValue() 新增 | ✅ |
| **jchains_hessian1_bcel** | vulnlab :8888 | ❌ ProxyLazyValue no trigger | LazyValue.createValue() 新增 | ✅ |
| jchains_hessian1_spring_exec | spring3 :8894 | ✅ PASS | — | ✅ |
| hessian2_spring (marshalsec) | vulnlab :8888 | ✅ PASS | — | ✅ |

### Section 4: Hessian2 链

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| jchains_hessian2_spring | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian2_spring2 | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian2_exec | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian2_rome1 | vulnlab :8888 | ✅ PASS | — | ✅ |
| **jchains_hessian2_rome2** | vulnlab :8888 | ❌ no callback | triggerGadgets SignedObject | 🔍 |
| **jchains_hessian2_secondary** | vulnlab :8888 | ❌ no callback | LazyValue.createValue() 新增 | ✅ |
| **jchains_hessian2_bcel** | vulnlab :8888 | ❌ no callback | LazyValue.createValue() 新增 | ✅ |
| jchains_hessian2_tostring_jackson | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian2_tostring_xbean | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_hessian2_spring_exec | spring3 :8894 | ✅ PASS | — | ✅ |

### Section 5: FastJSON 链

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| fastjson_jdbcrowset | vulnlab :8888 | ✅ PASS | — | ✅ |
| fastjson_jdbcrowset_v2 | vulnlab :8888 | ✅ PASS | — | ✅ |
| **fastjson_bcel** | vulnlab :8888 | ❌ getConnection() 未触发 | JSON.parse() 修复 | ✅ |
| jchains_fastjson | vulnlab :8888 | ✅ PASS | — | ✅ |
| **jchains_fastjson_bcel** | vulnlab :8888 | ❌ 同上 | JSON.parse() 修复 | ✅ |
| jchains_fastjson_jndi | vulnlab :8888 | ✅ PASS | — | ✅ |
| **jchains_fastjson_c3p0_h2** | vulnlab :8888 | ❌ sidecar 路由到 java-chains | sidecar 重建 + JSON.parse() | ✅ |

### Section 6: XStream 链

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| xstream_eventhandler | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_xstream | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_xstream_exec | vulnlab :8888 | ✅ PASS | — | ✅ |
| jchains_xstream_jndi | vulnlab :8888 | ✅ PASS | — | ✅ |

### Section 7: Log4Shell

| 链 ID | 靶机 | 上次状态 | 预期 |
|---|---|---|---|
| log4shell_vulnlab | vulnlab :8888 | ✅ PASS | ✅ |
| log4shell_dedicated | log4shell :8081 | ✅ PASS | ✅ |

### Section 8: Shiro

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| shiro_cbc | shiro :8082 | ✅ PASS | — | ✅ |
| shiro_gcm | shiro :8082 | ✅ PASS | — | ✅ |
| **jchains_shiro_cbc** | shiro :8082 | ❌ sidecar 路由到 java-chains 格式不符 | sidecar 重建(ChainRegistry fix) | ✅ |

### Section 9: C3P0 / H2

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| c3p0_jndi | vulnlab :8888 | ✅ PASS + RCE ✓ | — | ✅ |
| c3p0_wrapperds | vulnlab :8888 | ✅ PASS + RCE ✓ | — | ✅ |
| **jchains_h2_jdbc** | vulnlab :8888 | ⚠️ ERR (test code bug) | test_h2_jdbc() 独立函数 | ✅ |
| jchains_blazeds_axis2 | — | ⏭ AMF3 未搭建 | — | ⏭ |

### Section 10: JNDI ResourceRef 链

| 链 ID | 靶机 | 上次状态 | 本次修复 | 预期 |
|---|---|---|---|---|
| **jchains_jndi_tomcat_el** | vulnlab :8888 | ⏭ SKIP (旧测试代码) | test_jndi_ref_chain() + BeanFactory | ✅ |
| **jchains_jndi_groovy** | vulnlab :8888 | ⏭ SKIP (旧测试代码) | test_jndi_ref_chain() + BeanFactory | ✅ |
| **jchains_jndi_beanshell** | vulnlab :8888 | ⏭ SKIP (旧测试代码) | test_jndi_ref_chain() + BeanFactory | ✅ |
| jchains_jndi_snakeyaml | — | ⏭ SPI 需自定义 JAR 服务 | — | ⏭ |

### Section 11: Memshell 生成

| 组合 | 上次状态 | 预期 |
|---|---|---|
| tomcat filter/valve/listener/servlet/executor cmd | ✅ PASS | ✅ |
| tomcat filter behinder/godzilla/c2 | ✅ PASS | ✅ |
| spring interceptor/controller/webflux cmd | ✅ PASS | ✅ |
| jetty/jboss/weblogic filter cmd | ✅ PASS | ✅ |

### Section 12: C2 Memshell

| 链 ID | 上次状态 | 预期 |
|---|---|---|
| c2_memshell_serialize | ✅ PASS | ✅ |
| c2_memshell_jndi | ✅ PASS | ✅ |

---

## 🔢 预期结果

| 状态 | 上次 | 预期 |
|---|---|---|
| ✅ PASS | 56 | **83+** |
| ❌ FAIL | 22 | ≤4 (rome2 × 2 待观察) |
| ⏭ SKIP | 12 | 4 (urldns/blazeds/snakeyaml 不可达) |
| ⚠️ ERR | 2 | 0 |

---

## 🔍 不确定项（rome2 链）

`jchains_hessian1_rome2` / `jchains_hessian2_rome2`：  
- Hessian 将 `java.security.SignedObject` 序列化为 Map 格式，  
  `triggerGadgets` 的 `instanceof SignedObject` 可能不命中  
- 若仍失败，需在 triggerGadgets 增加从 Map 中重建 SignedObject 的逻辑，  
  或依赖 Hessian2 直接重建真实类型

---

## 已永久 SKIP 的链（有充分理由）

| 链 ID | 原因 |
|---|---|
| ysoserial_urldns | DNS-only，无 OOB DNS resolver |
| jchains_blazeds_axis2 | 需要 AMF3/BlazeDS 服务端，未搭建 |
| jchains_jndi_snakeyaml | SPI JAR loading 需自定义远程 JAR 服务 |
