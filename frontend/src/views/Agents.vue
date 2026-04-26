<template>
  <a-card title="Agent 管理 (C2)" :bordered="false">
    <template #extra>
      <a-button @click="load"><ReloadOutlined /> 刷新</a-button>
    </template>
    <a-table :data-source="agents" :columns="columns" :loading="loading" row-key="agent_id"
             size="small" @row-click="openConsole">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key==='status'">
          <a-badge :status="alive(record)?'processing':'default'"
                   :text="alive(record)?'在线':'离线'" />
        </template>
        <template v-if="column.key==='last_seen'">{{ fmtDate(record.last_seen) }}</template>
        <template v-if="column.key==='action'">
          <a-button size="small" type="primary" @click.stop="openConsole(record)">终端</a-button>
        </template>
      </template>
    </a-table>
  </a-card>

  <!-- Console drawer -->
  <a-drawer v-model:open="consoleOpen" :title="`Session — ${activeAgent?.agent_id}`"
            placement="right" width="660">
    <div class="console-box" ref="consoleEl">
      <div v-for="(l,i) in history" :key="i" :class="['console-line','type-'+l.type]">
        <span v-if="l.type==='cmd'" class="prompt">$ </span>{{ l.text }}
      </div>
    </div>
    <div class="flex gap-2 mt-3">
      <a-input v-model:value="cmdInput" placeholder="输入命令…" @press-enter="sendCmd"
               class="font-mono" :disabled="sending" />
      <a-button type="primary" @click="sendCmd" :loading="sending">执行</a-button>
    </div>
  </a-drawer>
</template>

<script setup lang="ts">
import { ref, onMounted, nextTick } from 'vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import { listAgents, sendCommand, listCommands } from '../api'

const agents = ref<any[]>([])
const loading = ref(false)
const consoleOpen = ref(false)
const activeAgent = ref<any>(null)
const cmdInput = ref('')
const sending = ref(false)
const history = ref<{type:string;text:string}[]>([])
const consoleEl = ref<HTMLElement>()

const columns = [
  { title: 'Agent ID', dataIndex:'agent_id', width:160 },
  { title: '框架', dataIndex:'framework', width:100 },
  { title: '主机', dataIndex:'hostname' },
  { title: '操作系统', dataIndex:'os', width:120 },
  { title: '最后活跃', key:'last_seen', dataIndex:'last_seen', width:160 },
  { title: '状态', key:'status', width:100 },
  { title: '', key:'action', width:80 },
]

function fmtDate(v: string) { return dayjs(v).format('MM-DD HH:mm:ss') }
function alive(r: any) { return dayjs().diff(dayjs(r.last_seen),'second') < 60 }

async function load() {
  loading.value = true
  try { agents.value = (await listAgents()).data }
  finally { loading.value = false }
}

async function openConsole(record: any) {
  activeAgent.value = record
  history.value = []
  consoleOpen.value = true
  try {
    const { data } = await listCommands(record.agent_id)
    for (const c of [...data].reverse()) {
      history.value.push({ type:'cmd', text:c.cmd })
      if (c.result) history.value.push({ type:'result', text:c.result })
    }
  } catch {}
}

async function sendCmd() {
  if (!cmdInput.value || !activeAgent.value) return
  const cmd = cmdInput.value; cmdInput.value = ''
  history.value.push({ type:'cmd', text:cmd })
  sending.value = true
  try {
    await sendCommand(activeAgent.value.agent_id, cmd)
    history.value.push({ type:'info', text:'↑ 已发送，等待 Agent 心跳回显…' })
    await new Promise(r => setTimeout(r, 2500))
    const { data } = await listCommands(activeAgent.value.agent_id)
    const latest = data[0]
    if (latest?.result) history.value.push({ type:'result', text:latest.result })
  } finally {
    sending.value = false
    await nextTick()
    consoleEl.value?.scrollTo(0, consoleEl.value.scrollHeight)
  }
}

onMounted(() => { load(); setInterval(load, 10000) })
</script>

<style scoped>
.console-box { background:#1a1a2e; color:#e6e6e6; font-family:monospace; font-size:12px; padding:12px; border-radius:8px; height:calc(100vh - 200px); overflow-y:auto; }
.console-line { margin-bottom:4px; line-height:1.6; white-space:pre-wrap; }
.type-cmd { color:#69b7ff; }
.type-result { color:#52c41a; }
.type-info { color:#8c8c8c; font-style:italic; }
.prompt { color:#8c8c8c; }
</style>
