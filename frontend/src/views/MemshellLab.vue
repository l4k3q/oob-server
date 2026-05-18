<template>
  <div class="ms-layout">
    <!-- Left config panel -->
    <div class="ms-config">
      <div class="ms-section-title">目标框架</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:16px">
        <div
          v-for="f in frameworks"
          :key="f"
          :class="['fw-btn', form.framework === f ? 'active' : '']"
          @click="selectFramework(f)"
        >{{ f }}</div>
      </div>

      <div class="ms-section-title">注入类型</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:16px">
        <div
          v-for="t in types[form.framework]"
          :key="t"
          :class="['type-btn', form.type === t ? 'active' : '']"
          @click="form.type = t"
          style="flex:1 1 auto;min-width:52px;max-width:72px;text-align:center"
        >{{ t }}</div>
      </div>

      <a-divider style="margin:12px 0" />

      <div class="ms-section-title">Shell 配置</div>
      <a-form layout="vertical" size="small">
        <a-form-item label="Shell 类型">
          <a-radio-group v-model:value="form.shell_type" button-style="solid" size="small">
            <a-radio-button value="cmd">cmd</a-radio-button>
            <a-radio-button value="behinder">冰蝎</a-radio-button>
            <a-radio-button value="godzilla">哥斯拉</a-radio-button>
            <a-radio-button value="c2">C2 Agent</a-radio-button>
          </a-radio-group>
        </a-form-item>
        <a-form-item v-if="form.shell_type === 'c2'" label="OOBserver 地址">
          <a-input v-model:value="form.c2_url" placeholder="http://OOBserver:8015" />
        </a-form-item>
        <a-form-item label="Servlet API">
          <a-radio-group v-model:value="form.servlet_api" button-style="solid" size="small">
            <a-radio-button value="jakarta">jakarta (Tomcat 10+)</a-radio-button>
            <a-radio-button value="javax">javax (Tomcat 9)</a-radio-button>
          </a-radio-group>
        </a-form-item>
        <a-row :gutter="8">
          <a-col :span="14">
            <a-form-item label="URL 匹配">
              <a-input v-model:value="form.url_pattern" />
            </a-form-item>
          </a-col>
          <a-col :span="10">
            <a-form-item label="密码/密钥">
              <a-input v-model:value="form.password" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-divider style="margin:8px 0" />

        <div class="ms-section-title">投递方式</div>
        <a-form-item label="方式" style="margin-bottom:8px">
          <a-select v-model:value="form.deliver" style="width:100%">
            <a-select-option value="bytecode">bytecode — 下载 .class 文件</a-select-option>
            <a-select-option value="jndi_ldap">JNDI LDAP 重绑定</a-select-option>
            <a-select-option value="jndi_rmi">JNDI RMI 重绑定</a-select-option>
            <a-select-option value="serialize">反序列化链包裹</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item v-if="form.deliver === 'serialize'" label="反序列化链（包裹内存马）">
          <a-select v-model:value="form.serialize_chain" style="width:100%">
            <a-select-opt-group label="Commons Collections">
              <a-select-option v-for="c in ['ysoserial_cc6','ysoserial_cc1','ysoserial_cc2','ysoserial_cc7']" :key="c" :value="c">{{ c }}</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Commons BeanUtils">
              <a-select-option value="ysoserial_cb1">ysoserial_cb1</a-select-option>
              <a-select-option value="cb_no_cc">cb_no_cc (无CC依赖)</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Spring / ROME">
              <a-select-option value="ysoserial_spring1">ysoserial_spring1</a-select-option>
              <a-select-option value="ysoserial_rome">ysoserial_rome</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Shiro 一键">
              <a-select-option value="shiro_cbc">shiro_cbc (AES-CBC)</a-select-option>
              <a-select-option value="shiro_gcm">shiro_gcm (AES-GCM)</a-select-option>
            </a-select-opt-group>
          </a-select>
        </a-form-item>
        <a-form-item
          v-if="['jndi_ldap','jndi_rmi'].includes(form.deliver)"
          label="OOB Token（JNDI 投递必填）"
        >
          <a-select v-model:value="form.token" allow-clear placeholder="选择 Token" style="width:100%">
            <a-select-option v-for="t in tokens" :key="t.token" :value="t.token">
              <span style="font-family:monospace;font-size:12px">{{ t.token }}</span>
              <span v-if="t.label" style="color:#8c8c8c;font-size:11px"> — {{ t.label }}</span>
            </a-select-option>
          </a-select>
        </a-form-item>
      </a-form>

      <a-button type="primary" block @click="gen" :loading="generating" style="margin-top:4px">
        <ThunderboltOutlined /> 生成内存马
      </a-button>
    </div>

    <!-- Right result panel -->
    <div class="ms-result">
      <template v-if="result">
        <a-card :bordered="false" size="small" class="ms-card">
          <template #title>
            <div class="flex items-center gap-2">
              <span style="font-weight:600">{{ result.framework }} / {{ result.type }}</span>
              <a-tag color="blue" style="margin:0;font-family:monospace;font-size:11px">{{ result.class_name }}</a-tag>
              <a-tag :color="shellColor[result.meta?.shell_type]" style="margin:0">{{ result.meta?.shell_type }}</a-tag>
            </div>
          </template>
          <template #extra>
            <a-space size="small">
              <a-button size="small" v-if="result.bytecode_b64" @click="downloadClass" type="primary" ghost>下载 .class</a-button>
              <a-button size="small" v-if="result.bytecode_b64" @click="copyB64">复制 Base64</a-button>
            </a-space>
          </template>

          <a-descriptions :column="3" size="small" bordered style="margin-bottom:12px">
            <a-descriptions-item label="框架">{{ result.framework }}</a-descriptions-item>
            <a-descriptions-item label="注入类型">{{ result.type }}</a-descriptions-item>
            <a-descriptions-item label="Shell">{{ result.meta?.shell_type }}</a-descriptions-item>
            <a-descriptions-item label="API">{{ result.meta?.servlet_api }}</a-descriptions-item>
            <a-descriptions-item label="URL 匹配">{{ result.meta?.url_pattern }}</a-descriptions-item>
            <a-descriptions-item label="类名" :span="1">
              <span style="font-family:monospace;font-size:11px">{{ result.class_name }}</span>
            </a-descriptions-item>
          </a-descriptions>

          <!-- Delivery payload -->
          <template v-if="result.payload">
            <a-divider orientation="left" plain style="font-size:12px;margin:8px 0">投递 Payload</a-divider>
            <div style="display:flex;gap:8px;align-items:center">
              <a-tag style="min-width:70px;text-align:center">{{ result.payload.type }}</a-tag>
              <a-input
                :value="result.payload.value"
                read-only
                style="flex:1;font-family:monospace;font-size:11px"
                size="small"
              />
              <a-button size="small" type="primary" @click="copy(result.payload.value)">复制</a-button>
            </div>
          </template>

          <!-- Bytecode -->
          <template v-if="result.bytecode_b64">
            <a-divider orientation="left" plain style="font-size:12px;margin:8px 0">字节码 (Base64)</a-divider>
            <a-textarea
              :value="result.bytecode_b64"
              :rows="4"
              read-only
              style="font-family:monospace;font-size:11px;background:#f6f8fa"
            />
          </template>
        </a-card>
      </template>

      <div v-else class="ms-empty">
        <a-empty>
          <template #description>
            <div style="color:#bfbfbf;font-size:13px">
              <p>配置参数后点击「生成内存马」</p>
              <div class="tip-grid">
                <div class="tip-item"><span class="tip-badge tomcat">Tomcat</span> Filter / Valve / Listener / Servlet</div>
                <div class="tip-item"><span class="tip-badge spring">Spring</span> Interceptor / Controller</div>
                <div class="tip-item"><span class="tip-badge jetty">Jetty/JBoss/WL</span> Filter</div>
                <div class="tip-item"><span class="tip-badge shell">Shell</span> cmd / 冰蝎 / 哥斯拉</div>
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
import { ThunderboltOutlined } from '@ant-design/icons-vue'
import { generateMemshell, listTokens } from '../api'

const frameworks = ['tomcat', 'spring', 'jetty', 'jboss', 'weblogic']
const types: Record<string, string[]> = {
  tomcat:   ['filter', 'servlet', 'listener', 'valve', 'executor'],
  spring:   ['interceptor', 'controller', 'webflux'],
  jetty:    ['filter'],
  jboss:    ['filter'],
  weblogic: ['filter'],
}
const shellColor: Record<string, string> = { cmd: 'default', behinder: 'orange', godzilla: 'purple', c2: 'cyan' }

const form = ref({
  framework: 'tomcat', type: 'filter', shell_type: 'cmd',
  servlet_api: 'jakarta', url_pattern: '/favicon.ico',
  password: 'cmd', deliver: 'bytecode', token: '',
  c2_url: `${location.protocol}//${location.hostname}:8015`,
  serialize_chain: 'ysoserial_cc6',
})
const tokens = ref<any[]>([])
const generating = ref(false)
const result = ref<any>(null)

function selectFramework(f: string) {
  form.value.framework = f
  form.value.type = types[f][0]
}

function copy(v: string) { navigator.clipboard.writeText(v); message.success('已复制') }
function copyB64() { if (result.value?.bytecode_b64) copy(result.value.bytecode_b64) }

async function gen() {
  generating.value = true
  try {
    const p: Record<string, any> = {
      shell_type: form.value.shell_type,
      servlet_api: form.value.servlet_api,
      url_pattern: form.value.url_pattern,
      password: form.value.password,
    }
    if (form.value.token) p.token = form.value.token
    if (form.value.shell_type === 'c2') p.__c2 = form.value.c2_url
    const { data } = await generateMemshell({
      framework: form.value.framework,
      type: form.value.type,
      params: p,
      token: form.value.token || undefined,
      deliver: form.value.deliver,
      serialize_chain: form.value.deliver === 'serialize' ? form.value.serialize_chain : undefined,
    })
    result.value = data
  } catch (e: any) {
    message.error(e.response?.data?.detail || e.message)
  } finally { generating.value = false }
}

function downloadClass() {
  if (!result.value?.bytecode_b64) return
  const bin = atob(result.value.bytecode_b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([bytes], { type: 'application/java-vm' }))
  a.download = (result.value.class_name || 'MemShell') + '.class'
  a.click()
}

onMounted(async () => { tokens.value = (await listTokens()).data })
</script>

<style scoped>
.ms-layout { display: flex; gap: 12px; height: calc(100vh - 110px); }

.ms-config {
  width: 320px;
  flex-shrink: 0;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  padding: 16px;
  overflow-y: auto;
}
.ms-config::-webkit-scrollbar { width: 4px; }
.ms-config::-webkit-scrollbar-thumb { background: #e8e8e8; border-radius: 2px; }

.ms-section-title {
  font-size: 12px;
  font-weight: 600;
  color: #8c8c8c;
  text-transform: uppercase;
  letter-spacing: .5px;
  margin-bottom: 8px;
}

.fw-btn {
  text-align: center;
  padding: 6px 0;
  border-radius: 6px;
  border: 1px solid #e8e8e8;
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
  color: #595959;
  background: #fafafa;
  transition: all .15s;
  margin-bottom: 6px;
}
.fw-btn:hover { border-color: #1677ff; color: #1677ff; background: #e8f4ff; }
.fw-btn.active { border-color: #1677ff; color: #fff; background: #1677ff; }

.type-btn {
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid #e8e8e8;
  cursor: pointer;
  font-size: 12px;
  color: #595959;
  background: #fafafa;
  transition: all .15s;
}
.type-btn:hover { border-color: #1677ff; color: #1677ff; }
.type-btn.active { border-color: #1677ff; color: #fff; background: #1677ff; }

.ms-result {
  flex: 1;
  overflow-y: auto;
  min-width: 0;
}
.ms-result::-webkit-scrollbar { width: 4px; }
.ms-card {
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
}
.ms-empty {
  height: 100%;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  display: flex;
  align-items: center;
  justify-content: center;
}
.tip-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; text-align: left; }
.tip-item { font-size: 12px; display: flex; align-items: center; gap: 6px; }
.tip-badge {
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 600;
  flex-shrink: 0;
}
.tip-badge.tomcat { background: #fff1f0; color: #cf1322; }
.tip-badge.spring { background: #f6ffed; color: #389e0d; }
.tip-badge.jetty  { background: #e6f4ff; color: #0958d9; }
.tip-badge.shell  { background: #f9f0ff; color: #531dab; }
</style>
