<template>
  <div>
    <!-- Stat cards -->
    <a-row :gutter="12" style="margin-bottom:16px">
      <a-col :span="6">
        <div class="stat-card">
          <div class="stat-label">近5分钟回连</div>
          <div class="stat-value" style="color:#52c41a">
            <WifiOutlined style="font-size:18px;margin-right:6px" />{{ onlineCount }}
          </div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="stat-card">
          <div class="stat-label">Token 总数</div>
          <div class="stat-value" style="color:#1677ff">
            <KeyOutlined style="font-size:18px;margin-right:6px" />{{ tokenCount }}
          </div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="stat-card">
          <div class="stat-label">事件累计</div>
          <div class="stat-value" style="color:#fa8c16">
            <ThunderboltOutlined style="font-size:18px;margin-right:6px" />{{ eventCount }}
          </div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="stat-card">
          <div class="stat-label">在线 Agent</div>
          <div class="stat-value" style="color:#722ed1">
            <DesktopOutlined style="font-size:18px;margin-right:6px" />{{ agentCount }}
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- Server info -->
    <div class="sys-card" style="margin-bottom:16px">
      <div class="sys-header">
        <span class="sys-title"><CloudServerOutlined style="margin-right:6px"/>服务器状态</span>
        <a-button size="small" @click="loadSysInfo" :loading="sysLoading">刷新</a-button>
      </div>
      <a-row :gutter="16" style="padding:12px 16px">
        <a-col :span="8">
          <div class="sys-metric-label">CPU 使用率</div>
          <a-progress :percent="sysInfo.cpu_percent ?? 0" :stroke-color="gaugeColor(sysInfo.cpu_percent)" size="small" />
          <div class="sys-metric-val">{{ sysInfo.cpu_percent >= 0 ? sysInfo.cpu_percent + '%' : '—' }}</div>
        </a-col>
        <a-col :span="8">
          <div class="sys-metric-label">内存使用</div>
          <a-progress :percent="sysInfo.mem?.percent ?? 0" :stroke-color="gaugeColor(sysInfo.mem?.percent)" size="small" />
          <div class="sys-metric-val">{{ sysInfo.mem ? `${sysInfo.mem.used_mb} / ${sysInfo.mem.total_mb} MB` : '—' }}</div>
        </a-col>
        <a-col :span="8">
          <div class="sys-metric-label">磁盘使用</div>
          <a-progress :percent="sysInfo.disk?.percent ?? 0" :stroke-color="gaugeColor(sysInfo.disk?.percent)" size="small" />
          <div class="sys-metric-val">{{ sysInfo.disk ? `${sysInfo.disk.used_gb} / ${sysInfo.disk.total_gb} GB` : '—' }}</div>
        </a-col>
      </a-row>
      <div v-if="sysInfo.uptime_s" style="padding:0 16px 10px;font-size:12px;color:#8c8c8c">
        运行时长: {{ fmtUptime(sysInfo.uptime_s) }}
        <span v-if="sysInfo.load_avg?.length" style="margin-left:16px">
          负载: {{ sysInfo.load_avg.join(' / ') }}
        </span>
      </div>
    </div>

    <!-- Live stream card -->
    <div class="stream-card">
      <div class="stream-header">
        <span class="stream-title">实时回连流</span>
        <div style="display:flex;align-items:center;gap:8px">
          <a-badge :status="wsConnected ? 'processing' : 'error'" :text="wsConnected ? 'WS 已连接' : '未连接'" />
          <a-select
            :value="filterProto"
            size="small"
            allow-clear
            placeholder="协议筛选"
            style="width:100px"
            @change="(v: any) => filterProto = v ?? ''"
          >
            <a-select-option v-for="p in ['http','ldap','rmi','tcp','dns']" :key="p" :value="p">{{ p.toUpperCase() }}</a-select-option>
          </a-select>
          <a-button size="small" @click="events=[]">清空</a-button>
        </div>
      </div>

      <div class="stream-table-wrap">
        <table class="stream-table">
          <thead>
            <tr>
              <th style="width:72px">协议</th>
              <th style="width:140px">来源 IP</th>
              <th style="width:120px">Token</th>
              <th>摘要</th>
              <th style="width:115px">时间</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="filteredEvents.length === 0">
              <td colspan="5" style="text-align:center;padding:40px 0;color:#bfbfbf;font-size:13px">
                等待回连…
              </td>
            </tr>
            <tr v-for="ev in filteredEvents" :key="ev.id" class="stream-row">
              <td><span :class="['proto-tag','proto-'+ev.protocol]">{{ ev.protocol.toUpperCase() }}</span></td>
              <td class="mono">{{ ev.remote_addr }}</td>
              <td><span v-if="ev.token" class="token-tag">{{ ev.token }}</span></td>
              <td class="summary-cell" :title="ev.summary">{{ ev.summary }}</td>
              <td class="mono time-cell">{{ fmtTime(ev.created_at) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
  WifiOutlined, KeyOutlined, ThunderboltOutlined,
  DesktopOutlined, CloudServerOutlined
} from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import api, { listTokens, listAgents } from '../api'

const events = ref<any[]>([])
const wsConnected = ref(false)
const filterProto = ref('')
const onlineCount = ref(0)
const tokenCount = ref(0)
const eventCount = ref(0)
const agentCount = ref(0)
const sysInfo = ref<any>({})
const sysLoading = ref(false)
let ws: WebSocket | null = null
let idCounter = 0

const filteredEvents = computed(() =>
  filterProto.value
    ? events.value.filter(e => e.protocol === filterProto.value)
    : events.value
)

function fmtTime(v: string) { return dayjs(v).format('HH:mm:ss.SSS') }

function fmtUptime(s: number): string {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

function gaugeColor(p?: number): string {
  if (p == null) return '#1677ff'
  if (p > 90) return '#ff4d4f'
  if (p > 70) return '#fa8c16'
  return '#52c41a'
}

function connect() {
  const token = localStorage.getItem('oobx_token') || ''
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${proto}://${location.host}/ws/events?access_token=${token}`)
  ws.onopen  = () => { wsConnected.value = true }
  ws.onmessage = (e) => {
    const ev = JSON.parse(e.data)
    if (ev.type === 'pong' || ev.protocol === 'ping') return
    events.value.unshift({ ...ev, id: idCounter++ })
    eventCount.value++
    if (events.value.length > 500) events.value = events.value.slice(0, 500)
  }
  ws.onclose = () => { wsConnected.value = false; setTimeout(connect, 3000) }
  ws.onerror = () => ws?.close()
}

async function loadStats() {
  try {
    const [tokRes, agentRes] = await Promise.all([listTokens(), listAgents()])
    tokenCount.value = tokRes.data.length
    agentCount.value = agentRes.data.filter((a: any) =>
      dayjs().diff(dayjs(a.last_seen), 'second') < 60
    ).length
    onlineCount.value = events.value.filter(e =>
      dayjs().diff(dayjs(e.created_at), 'second') < 300
    ).length
  } catch {}
}

async function loadSysInfo() {
  sysLoading.value = true
  try {
    const res = await api.get('/system/info')
    sysInfo.value = res.data
  } catch {}
  finally { sysLoading.value = false }
}

let statsTimer: ReturnType<typeof setInterval> | null = null
let sysTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  connect()
  loadStats()
  loadSysInfo()
  statsTimer = setInterval(loadStats, 15000)
  sysTimer   = setInterval(loadSysInfo, 30000)
})
onUnmounted(() => {
  ws?.close()
  if (statsTimer) clearInterval(statsTimer)
  if (sysTimer)   clearInterval(sysTimer)
})
</script>

<style scoped>
.stat-card {
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  padding: 16px 20px;
}
.stat-label { font-size: 13px; color: #8c8c8c; margin-bottom: 8px; }
.stat-value { font-size: 28px; font-weight: 700; display: flex; align-items: center; }

.sys-card { background: #fff; border-radius: 8px; border: 1px solid #f0f0f0; overflow: hidden; }
.sys-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 16px; border-bottom: 1px solid #f0f0f0;
}
.sys-title { font-size: 14px; font-weight: 600; color: #262626; }
.sys-metric-label { font-size: 12px; color: #8c8c8c; margin-bottom: 4px; }
.sys-metric-val { font-size: 12px; color: #595959; margin-top: 4px; font-family: monospace; }

.stream-card { background: #fff; border-radius: 8px; border: 1px solid #f0f0f0; overflow: hidden; }
.stream-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px; border-bottom: 1px solid #f0f0f0;
}
.stream-title { font-size: 14px; font-weight: 600; color: #262626; }
.stream-table-wrap { height: calc(100vh - 390px); overflow-y: auto; }
.stream-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.stream-table thead th {
  position: sticky; top: 0; background: #fafafa;
  padding: 8px 12px; text-align: left; color: #8c8c8c;
  font-weight: 500; border-bottom: 1px solid #f0f0f0; z-index: 1;
}
.stream-row { border-bottom: 1px solid #fafafa; transition: background .1s; }
.stream-row:hover { background: #f9fbff; }
.stream-row td { padding: 7px 12px; vertical-align: middle; }
.proto-tag {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 11px; font-weight: 700;
}
.proto-http  { background:#f6ffed; color:#389e0d; border:1px solid #b7eb8f; }
.proto-ldap  { background:#fff7e6; color:#d46b08; border:1px solid #ffd591; }
.proto-rmi   { background:#fff1f0; color:#cf1322; border:1px solid #ffa39e; }
.proto-tcp   { background:#e6f4ff; color:#0958d9; border:1px solid #91caff; }
.proto-dns   { background:#f9f0ff; color:#531dab; border:1px solid #d3adf7; }
.token-tag {
  background:#e6f4ff; color:#0958d9; padding:1px 6px; border-radius:3px;
  font-family:monospace; font-size:11px; display:inline-block;
}
.mono { font-family: monospace; color: #595959; }
.summary-cell { max-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#262626; }
.time-cell { color:#8c8c8c; white-space:nowrap; }
</style>
