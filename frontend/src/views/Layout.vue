<template>
  <a-layout class="min-h-screen">
    <a-layout-header class="header">
      <div class="flex items-center h-full">
        <div class="logo">
          <ThunderboltFilled class="logo-icon" />
          <span>OOBserver</span>
        </div>
        <a-menu
          mode="horizontal"
          :selected-keys="activeKeys"
          class="flex-1 border-none header-menu"
          @click="onMenuClick"
        >
          <a-menu-item key="/dashboard"><DashboardOutlined />仪表盘</a-menu-item>
          <a-menu-item key="/projects"><FolderOutlined />项目管理</a-menu-item>
          <a-menu-item key="/tokens"><KeyOutlined />Token 管理</a-menu-item>
          <a-menu-item key="/events"><ThunderboltOutlined />回连事件</a-menu-item>
          <a-menu-item key="/payload-builder"><CodeOutlined />Payload 构造</a-menu-item>
          <a-menu-item key="/memshell-lab"><BugOutlined />内存马工坊</a-menu-item>
          <a-menu-item key="/compile-lab"><ExperimentOutlined />编译 Class</a-menu-item>
          <a-menu-item key="/agents"><DesktopOutlined />Agent (C2)</a-menu-item>
        </a-menu>
        <div class="flex items-center gap-3 mr-4">
          <a-tooltip :title="wsConnected ? `WS已连接 · 上次心跳 ${lastPingAgo}s前` : 'WS断开，正在重连...'">
            <div class="ws-indicator" :class="wsConnected ? 'connected' : 'disconnected'">
              <span class="ws-dot" />
              <span class="ws-label">{{ wsConnected ? '已连接' : '断开' }}</span>
            </div>
          </a-tooltip>
          <a-dropdown>
            <div class="flex items-center gap-1 cursor-pointer" style="color:#595959">
              <UserOutlined />
              <span style="font-size:13px">{{ auth.user?.username }}</span>
            </div>
            <template #overlay>
              <a-menu>
                <a-menu-item key="apikey" @click="showApiKey">API Key</a-menu-item>
                <a-menu-divider />
                <a-menu-item key="logout" @click="logout" danger>退出登录</a-menu-item>
              </a-menu>
            </template>
          </a-dropdown>
        </div>
      </div>
    </a-layout-header>

    <!-- Tab bar -->
    <div class="tab-bar">
      <div
        v-for="tab in tabs"
        :key="tab.path"
        :class="['tab-item', route.path === tab.path ? 'active' : '']"
        @click="router.push(tab.path)"
      >
        <component :is="tab.icon" style="margin-right:4px;font-size:12px" />
        {{ tab.label }}
        <CloseOutlined
          v-if="tabs.length > 1"
          class="tab-close"
          @click.stop="closeTab(tab.path)"
        />
      </div>
    </div>

    <a-layout-content class="page-content">
      <router-view />
    </a-layout-content>
  </a-layout>

  <a-modal v-model:open="apiKeyModal" title="API Key" :footer="null" width="500px">
    <p style="color:#8c8c8c;font-size:13px;margin-bottom:12px">用于脚本/自动化调用时代替 JWT Token，在 Header 中传 <code>X-API-Key</code></p>
    <a-input-group compact>
      <a-input :value="auth.user?.api_key" readonly style="width:calc(100% - 72px);font-family:monospace;font-size:12px" />
      <a-button type="primary" @click="copyApiKey">复制</a-button>
    </a-input-group>
    <div style="margin-top:12px">
      <a-button @click="rotateKey" :loading="rotating" size="small">轮换 Key</a-button>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import {
  DashboardOutlined, FolderOutlined, KeyOutlined, CodeOutlined,
  DesktopOutlined, UserOutlined, WifiOutlined, CloseOutlined,
  ThunderboltFilled, ThunderboltOutlined, BugOutlined, ExperimentOutlined
} from '@ant-design/icons-vue'
import { useAuthStore } from '../stores/auth'
import api from '../api'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const wsConnected = ref(false)
const lastPingAgo = ref(0)
const apiKeyModal = ref(false)
const rotating = ref(false)

const NAV_MAP: Record<string, { label: string; icon: any }> = {
  '/dashboard':       { label: '仪表盘',     icon: DashboardOutlined },
  '/projects':        { label: '项目管理',   icon: FolderOutlined },
  '/tokens':          { label: 'Token 管理', icon: KeyOutlined },
  '/events':          { label: '回连事件',   icon: ThunderboltOutlined },
  '/payload-builder': { label: 'Payload 构造', icon: CodeOutlined },
  '/memshell-lab':    { label: '内存马工坊', icon: BugOutlined },
  '/compile-lab':     { label: '编译 Class', icon: ExperimentOutlined },
  '/agents':          { label: 'Agent C2',  icon: DesktopOutlined },
}

const tabs = ref<{ path: string; label: string; icon: any }[]>([
  { path: '/dashboard', ...NAV_MAP['/dashboard'] }
])

// Use computed (read-only) for menu highlight — do NOT v-model this
const activeKeys = computed(() => [route.path])

function onMenuClick({ key }: { key: string }) {
  router.push(key)
  if (!tabs.value.find(t => t.path === key) && NAV_MAP[key]) {
    tabs.value.push({ path: key, ...NAV_MAP[key] })
  }
}

function closeTab(path: string) {
  const idx = tabs.value.findIndex(t => t.path === path)
  if (idx === -1) return
  tabs.value.splice(idx, 1)
  if (route.path === path) {
    router.push(tabs.value[Math.max(0, idx - 1)].path)
  }
}

watch(() => route.path, (p) => {
  if (!tabs.value.find(t => t.path === p) && NAV_MAP[p]) {
    tabs.value.push({ path: p, ...NAV_MAP[p] })
  }
})

function showApiKey() { apiKeyModal.value = true }
function copyApiKey() {
  navigator.clipboard.writeText(auth.user?.api_key || '')
  message.success('已复制')
}
async function rotateKey() {
  rotating.value = true
  try {
    await api.post('/auth/rotate-key')
    await auth.fetchMe()
    message.success('Key 已轮换')
  } finally { rotating.value = false }
}
function logout() { auth.logout(); router.push('/login') }

let ws: WebSocket | null = null
let pingTimer: ReturnType<typeof setInterval> | null = null
let lastPingTime = Date.now()

function connectWs() {
  const token = localStorage.getItem('oobx_token') || ''
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${proto}://${location.host}/ws/events?access_token=${token}`)
  ws.onopen = () => {
    wsConnected.value = true
    lastPingTime = Date.now()
    // Send a ping every 25s to keep connection alive
    pingTimer = setInterval(() => {
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }))
        lastPingTime = Date.now()
      }
    }, 25000)
  }
  ws.onclose = () => {
    wsConnected.value = false
    if (pingTimer) { clearInterval(pingTimer); pingTimer = null }
    setTimeout(connectWs, 4000)
  }
  ws.onerror = () => ws?.close()
}

// Update lastPingAgo every second
let agoTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  connectWs()
  agoTimer = setInterval(() => {
    lastPingAgo.value = Math.floor((Date.now() - lastPingTime) / 1000)
  }, 1000)
})
onUnmounted(() => {
  ws?.close()
  if (pingTimer) clearInterval(pingTimer)
  if (agoTimer) clearInterval(agoTimer)
})
</script>

<style scoped>
.header {
  background: #fff;
  padding: 0;
  height: 54px;
  line-height: 54px;
  border-bottom: 1px solid #f0f0f0;
  box-shadow: 0 1px 4px rgba(0,21,41,.06);
  position: sticky;
  top: 0;
  z-index: 100;
}
.logo {
  width: 180px;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 17px;
  font-weight: 700;
  color: #1677ff;
  padding-left: 20px;
  flex-shrink: 0;
}
.logo-icon { font-size: 20px; }
.header-menu { line-height: 52px; background: transparent; }
.tab-bar {
  display: flex;
  gap: 2px;
  padding: 5px 16px 0;
  background: #fff;
  border-bottom: 1px solid #f0f0f0;
  overflow-x: auto;
  min-height: 36px;
}
.tab-bar::-webkit-scrollbar { height: 0; }
.tab-item {
  display: inline-flex;
  align-items: center;
  padding: 3px 12px;
  border-radius: 4px 4px 0 0;
  border: 1px solid transparent;
  background: #f5f5f5;
  cursor: pointer;
  font-size: 13px;
  color: #595959;
  white-space: nowrap;
  transition: all .15s;
  user-select: none;
}
.tab-item:hover { background: #e8f4ff; color: #1677ff; }
.tab-item.active { background: #fff; color: #1677ff; border-color: #d9d9d9; border-bottom-color: #fff; font-weight: 500; }
.tab-close { margin-left: 6px; font-size: 10px; opacity: 0.4; transition: opacity .15s; }
.tab-close:hover { opacity: 1; color: #ff4d4f; }
.ws-indicator {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 2px 8px; border-radius: 10px; font-size: 12px; cursor: default;
  transition: all .3s;
}
.ws-indicator.connected   { background: #f6ffed; color: #52c41a; border: 1px solid #b7eb8f; }
.ws-indicator.disconnected { background: #fff2f0; color: #ff4d4f; border: 1px solid #ffccc7; }
.ws-dot {
  width: 7px; height: 7px; border-radius: 50%; display: inline-block;
}
.ws-indicator.connected .ws-dot {
  background: #52c41a;
  box-shadow: 0 0 0 0 rgba(82,196,26,.5);
  animation: pulse-green 2s infinite;
}
.ws-indicator.disconnected .ws-dot { background: #ff4d4f; }
@keyframes pulse-green {
  0%   { box-shadow: 0 0 0 0 rgba(82,196,26,.5); }
  70%  { box-shadow: 0 0 0 5px rgba(82,196,26,0); }
  100% { box-shadow: 0 0 0 0 rgba(82,196,26,0); }
}
.page-content {
  padding: 16px 20px;
  min-height: calc(100vh - 90px);
  background: #f5f7fa;
}
</style>
