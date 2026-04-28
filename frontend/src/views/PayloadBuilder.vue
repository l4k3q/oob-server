<template>
  <div class="pb-layout">
    <!-- Left config panel -->
    <div class="pb-config">
      <!-- Category selector -->
      <div class="ms-section-title">利用类型</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:5px;margin-bottom:14px">
        <div
          v-for="cat in categories"
          :key="cat.value"
          :class="['fw-btn', selectedCat === cat.value ? 'active' : '']"
          @click="selectCat(cat.value)"
        >{{ cat.label }}</div>
      </div>

      <!-- Chain picker: sub_category dropdown + flat chain list -->
      <div class="ms-section-title">选择利用链</div>
      <div v-if="catChains.length===0" style="color:#bfbfbf;font-size:12px;padding:4px;margin-bottom:14px">
        请先选择类型
      </div>
      <template v-else>
        <a-select
          v-model:value="selectedSub"
          style="width:100%;margin-bottom:10px"
          size="small"
          placeholder="全部分类"
          allow-clear
          @change="selected=null;result=null"
        >
          <a-select-option value="">全部</a-select-option>
          <a-select-option v-for="sub in catSubCategories" :key="sub" :value="sub">
            {{ sub }} <span style="color:#bfbfbf">({{ subCount(sub) }})</span>
          </a-select-option>
        </a-select>
        <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px">
          <div
            v-for="c in filteredChains"
            :key="c.id"
            :class="['type-btn', selected?.id === c.id ? 'active' : '']"
            @click="pick(c)"
            :title="c.description"
          >{{ c.name }}</div>
        </div>
      </template>

      <!-- Chain description -->
      <div v-if="selected" class="chain-desc-box">
        <div style="font-size:12px;color:#1677ff;font-weight:500;margin-bottom:4px">
          {{ selected.name }}
          <a-tag v-if="selected.requires_sidecar" color="orange" style="margin-left:4px;font-size:10px">需要 sidecar</a-tag>
        </div>
        <div style="font-size:12px;color:#8c8c8c;line-height:1.5">{{ selected.description }}</div>
      </div>

      <a-divider style="margin:12px 0" v-if="selected" />

      <!-- Parameters -->
      <template v-if="selected">
        <div class="ms-section-title">参数配置</div>
        <a-form layout="vertical" size="small">
          <a-form-item
            v-for="p in selected.params"
            :key="p.name"
            :label="p.name + (p.required ? ' *' : '')"
            style="margin-bottom:10px"
          >
            <a-select v-if="p.type==='select'" v-model:value="params[p.name]" style="width:100%">
              <a-select-option v-for="o in p.options" :key="o" :value="o">{{ o }}</a-select-option>
            </a-select>
            <a-select v-else-if="p.name==='token'" v-model:value="params[p.name]" allow-clear placeholder="选择 Token" style="width:100%">
              <a-select-option v-for="t in tokens" :key="t.token" :value="t.token">
                <span style="font-family:monospace;font-size:12px">{{ t.token }}</span>
                <span v-if="t.label" style="color:#8c8c8c;font-size:11px"> — {{ t.label }}</span>
              </a-select-option>
            </a-select>
            <a-input v-else-if="p.type==='string'" v-model:value="params[p.name]" :placeholder="p.description||p.name" />
            <a-input-number v-else-if="p.type==='int'" v-model:value="params[p.name]" style="width:100%" />
          </a-form-item>
        </a-form>

        <a-button type="primary" block @click="gen" :loading="generating" style="margin-top:4px">
          <ThunderboltOutlined /> 生成 Payload
        </a-button>
      </template>
    </div>

    <!-- Right result panel -->
    <div class="pb-result-area">
      <template v-if="result">
        <div class="ms-card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <div class="flex items-center gap-2">
              <span style="font-weight:600;font-size:14px">生成结果</span>
              <a-tag :color="CAT_COLOR[selected?.category]||'default'" style="margin:0">{{ CAT_LABEL[selected?.category] }}</a-tag>
              <a-tag style="font-family:monospace;font-size:11px;margin:0">{{ result.content_type }}</a-tag>
            </div>
            <a-space size="small">
              <a-button size="small" @click="copy(result.value)">复制</a-button>
              <a-button size="small" type="primary" ghost v-if="isBin" @click="download">下载</a-button>
            </a-space>
          </div>

          <div class="result-code">{{ result.value }}</div>

          <template v-if="result.urls && Object.keys(result.urls).length">
            <a-divider orientation="left" plain style="font-size:12px;margin:12px 0 8px">附加 URL</a-divider>
            <div v-for="(v, k) in result.urls" :key="k" style="display:flex;gap:8px;align-items:center;margin-bottom:6px">
              <a-tag style="min-width:90px;text-align:center;font-size:11px;flex-shrink:0">{{ k }}</a-tag>
              <a-input :value="String(v)" read-only style="flex:1;font-family:monospace;font-size:11px" size="small" />
              <a-button size="small" @click="copy(String(v))">复制</a-button>
            </div>
          </template>

          <template v-if="result.meta && Object.keys(result.meta).length">
            <a-divider orientation="left" plain style="font-size:12px;margin:12px 0 8px">附加信息</a-divider>
            <a-descriptions :column="2" size="small" bordered>
              <a-descriptions-item v-for="(v, k) in result.meta" :key="k" :label="String(k)">
                <span style="font-family:monospace;font-size:11px;word-break:break-all">{{ v }}</span>
              </a-descriptions-item>
            </a-descriptions>
          </template>
        </div>
      </template>

      <div v-else class="pb-empty-area">
        <a-empty>
          <template #description>
            <div style="color:#bfbfbf;font-size:13px">
              <p>← 从左侧选择利用类型和利用链</p>
              <div class="tip-grid">
                <div class="tip-item"><span class="tip-badge" style="background:#fff1f0;color:#cf1322">序列化</span>CC1-7 / CB1 / Spring / ROME / Groovy</div>
                <div class="tip-item"><span class="tip-badge" style="background:#fff7e6;color:#d46b08">JNDI</span>LDAP Basic / EL / BCEL / Deserialize</div>
                <div class="tip-item"><span class="tip-badge" style="background:#e6f4ff;color:#0958d9">外带</span>Log4j / FastJson / Shiro / SnakeYAML</div>
                <div class="tip-item"><span class="tip-badge" style="background:#f9f0ff;color:#531dab">内存马</span>Tomcat Filter/Valve/Listener...</div>
                <div class="tip-item"><span class="tip-badge" style="background:#f6ffed;color:#389e0d">盲打</span>sleep / ping / HTTP / SMB / DNS</div>
                <div class="tip-item"><span class="tip-badge" style="background:#fafafa;color:#595959">通用</span>搜索框可模糊搜索</div>
              </div>
            </div>
          </template>
        </a-empty>

        <!-- Quick search fallback -->
        <div style="margin-top:16px;padding:0 20px">
          <a-input-search
            v-model:value="quickSearch"
            placeholder="快速搜索…"
            allow-clear
            size="small"
            @change="onQuickSearch"
          />
          <div v-if="quickSearch && searchResults.length" class="search-results">
            <div
              v-for="c in searchResults"
              :key="c.id"
              class="search-item"
              @click="pickAndClear(c)"
            >
              <a-tag :color="CAT_COLOR[c.category]" style="font-size:10px;margin-right:4px;padding:0 4px">{{ CAT_LABEL[c.category] }}</a-tag>
              <span style="font-size:13px">{{ c.name }}</span>
              <span style="color:#8c8c8c;font-size:11px;margin-left:4px">{{ c.sub_category }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { ThunderboltOutlined } from '@ant-design/icons-vue'
import { getPayloadCatalog, generatePayload, listTokens } from '../api'

const CAT_COLOR: Record<string, string> = {
  serialize: 'red', jndi: 'orange', exfil: 'blue', memshell: 'purple', blind: 'green'
}
const CAT_LABEL: Record<string, string> = {
  serialize: '序列化', jndi: 'JNDI注入', exfil: '外带/Exfil', memshell: '内存马', blind: '盲打/不出网'
}
const categories = [
  { value: 'serialize', label: '序列化' },
  { value: 'jndi',      label: 'JNDI注入' },
  { value: 'exfil',     label: '外带' },
  { value: 'memshell',  label: '内存马' },
  { value: 'blind',     label: '盲打' },
]

const catalog = ref<any[]>([])
const tokens = ref<any[]>([])
const selectedCat = ref('serialize')
const selected = ref<any>(null)
const params = ref<Record<string, any>>({})
const generating = ref(false)
const result = ref<any>(null)
const quickSearch = ref('')
const searchResults = ref<any[]>([])

const selectedSub = ref('')

const catChains = computed(() =>
  catalog.value.filter(c => c.category === selectedCat.value)
)

const catSubCategories = computed(() => {
  const seen = new Set<string>()
  const list: string[] = []
  for (const c of catChains.value) {
    const sub = c.sub_category || '其他'
    if (!seen.has(sub)) { seen.add(sub); list.push(sub) }
  }
  return list
})

const filteredChains = computed(() =>
  selectedSub.value
    ? catChains.value.filter(c => c.sub_category === selectedSub.value)
    : catChains.value
)

function subCount(sub: string) {
  return catChains.value.filter(c => c.sub_category === sub).length
}

const isBin = computed(() =>
  result.value?.content_type === 'application/java-vm' ||
  result.value?.content_type === 'application/octet-stream'
)

function selectCat(cat: string) {
  selectedCat.value = cat
  selectedSub.value = ''
  selected.value = null
  result.value = null
}

function pick(c: any) {
  selected.value = c
  result.value = null
  params.value = {}
  for (const p of c.params) {
    params.value[p.name] = p.default ?? (p.type === 'bool' ? false : p.type === 'int' ? (p.default ?? 0) : '')
  }
}

function onQuickSearch() {
  if (!quickSearch.value) { searchResults.value = []; return }
  const q = quickSearch.value.toLowerCase()
  searchResults.value = catalog.value.filter(c =>
    c.name.toLowerCase().includes(q) ||
    c.tags.some((t: string) => t.toLowerCase().includes(q)) ||
    c.description.toLowerCase().includes(q)
  ).slice(0, 8)
}

function pickAndClear(c: any) {
  selectedCat.value = c.category
  pick(c)
  quickSearch.value = ''
  searchResults.value = []
}

async function gen() {
  if (!selected.value) return
  generating.value = true
  try {
    const { data } = await generatePayload({ type: selected.value.id, params: params.value })
    result.value = data
  } catch (e: any) {
    message.error(e.response?.data?.detail || e.message)
  } finally { generating.value = false }
}

function copy(v: string) { navigator.clipboard.writeText(v); message.success('已复制') }

function download() {
  if (!result.value?.value) return
  const bin = atob(result.value.value)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }))
  a.download = (selected.value?.id || 'payload') + '.bin'
  a.click()
}

onMounted(async () => {
  [catalog.value, tokens.value] = await Promise.all([
    getPayloadCatalog().then(r => r.data),
    listTokens().then(r => r.data),
  ])
})
</script>

<style scoped>
.pb-layout {
  display: flex;
  gap: 12px;
  height: calc(100vh - 110px);
}

/* Left panel — same style as MemshellLab */
.pb-config {
  width: 300px;
  flex-shrink: 0;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  padding: 16px;
  overflow-y: auto;
}
.pb-config::-webkit-scrollbar { width: 4px; }
.pb-config::-webkit-scrollbar-thumb { background: #e8e8e8; border-radius: 2px; }

.ms-section-title {
  font-size: 11px;
  font-weight: 700;
  color: #8c8c8c;
  text-transform: uppercase;
  letter-spacing: .5px;
  margin-bottom: 8px;
}
.fw-btn {
  text-align: center;
  padding: 6px 4px;
  border-radius: 6px;
  border: 1px solid #e8e8e8;
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
  color: #595959;
  background: #fafafa;
  transition: all .15s;
}
.fw-btn:hover { border-color: #1677ff; color: #1677ff; background: #e8f4ff; }
.fw-btn.active { border-color: #1677ff; color: #fff; background: #1677ff; }

.type-btn {
  padding: 3px 10px;
  border-radius: 20px;
  border: 1px solid #e8e8e8;
  cursor: pointer;
  font-size: 11px;
  color: #595959;
  background: #fafafa;
  transition: all .15s;
  white-space: nowrap;
}
.type-btn:hover { border-color: #1677ff; color: #1677ff; }
.type-btn.active { border-color: #1677ff; color: #fff; background: #1677ff; }

.sub-cat-label {
  font-size: 10px;
  font-weight: 700;
  color: #bfbfbf;
  text-transform: uppercase;
  letter-spacing: .6px;
  margin-bottom: 5px;
  padding-left: 2px;
}

.chain-desc-box {
  background: #f9fbff;
  border: 1px solid #e6f4ff;
  border-radius: 6px;
  padding: 8px 10px;
  margin-bottom: 2px;
}

/* Right panel */
.pb-result-area {
  flex: 1;
  overflow-y: auto;
  min-width: 0;
}
.pb-result-area::-webkit-scrollbar { width: 4px; }
.ms-card {
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  padding: 16px;
  height: 100%;
}
.pb-empty-area {
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
.result-code {
  background: #f6f8fa;
  border: 1px solid #e8e8e8;
  border-radius: 6px;
  padding: 10px 12px;
  font-family: 'Cascadia Code','Fira Code',Consolas,monospace;
  font-size: 12px;
  color: #d32029;
  word-break: break-all;
  white-space: pre-wrap;
  max-height: 200px;
  overflow: auto;
}
.tip-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin-top: 12px;
  text-align: left;
  padding: 0 20px;
}
.tip-item { font-size: 12px; display: flex; align-items: center; gap: 6px; }
.tip-badge {
  padding: 2px 6px; border-radius: 3px; font-size: 11px;
  font-weight: 600; flex-shrink: 0;
}
.search-results {
  background: #fff;
  border: 1px solid #f0f0f0;
  border-radius: 6px;
  margin-top: 4px;
  max-height: 240px;
  overflow-y: auto;
}
.search-item {
  padding: 8px 12px;
  cursor: pointer;
  display: flex;
  align-items: center;
  border-bottom: 1px solid #fafafa;
  transition: background .1s;
}
.search-item:hover { background: #f0f7ff; }
.search-item:last-child { border-bottom: none; }
</style>
