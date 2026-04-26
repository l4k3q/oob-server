<template>
  <a-card title="回连事件" :bordered="false">
    <template #extra>
      <a-space>
        <a-select v-model:value="filterProto" style="width:100px" allow-clear placeholder="协议">
          <a-select-option v-for="p in ['http','ldap','rmi','tcp','dns']" :key="p" :value="p">{{p.toUpperCase()}}</a-select-option>
        </a-select>
        <a-input-search v-model:value="search" placeholder="搜索 token/IP/摘要" style="width:240px" allow-clear />
        <a-button @click="load"><ReloadOutlined /> 刷新</a-button>
      </a-space>
    </template>
    <a-table
      :data-source="filtered"
      :columns="columns"
      :loading="loading"
      size="small"
      row-key="id"
      :pagination="{pageSize:100, showTotal: (t: number) => `共 ${t} 条`}"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key==='protocol'">
          <a-tag :color="COLORS[record.protocol]||'default'">{{ record.protocol.toUpperCase() }}</a-tag>
        </template>
        <template v-if="column.key==='token'">
          <a-tag v-if="record.token_id" color="blue" size="small">{{ record.token_id }}</a-tag>
        </template>
        <template v-if="column.key==='created_at'">{{ fmtTime(record.created_at) }}</template>
        <template v-if="column.key==='raw'">
          <a-button size="small" @click="viewRaw(record)">详情</a-button>
        </template>
      </template>
    </a-table>
  </a-card>

  <a-modal v-model:open="rawModal" title="原始数据" width="700px" :footer="null">
    <pre class="raw-pre">{{ JSON.stringify(rawData, null, 2) }}</pre>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import api from '../api'

const COLORS: Record<string,string> = { http:'green',ldap:'orange',rmi:'red',tcp:'blue',dns:'purple' }
const events = ref<any[]>([])
const loading = ref(false)
const filterProto = ref<string|undefined>()
const search = ref('')
const rawModal = ref(false)
const rawData = ref<any>(null)

const columns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '协议', key: 'protocol', dataIndex: 'protocol', width: 80 },
  { title: '来源', dataIndex: 'remote_addr', width: 140 },
  { title: 'Token', key: 'token', width: 100 },
  { title: '摘要', dataIndex: 'summary', ellipsis: true },
  { title: '时间', key: 'created_at', dataIndex: 'created_at', width: 150 },
  { title: '', key: 'raw', width: 70 },
]

const filtered = computed(() => {
  let r = events.value
  if (filterProto.value) r = r.filter(e => e.protocol === filterProto.value)
  if (search.value) {
    const q = search.value.toLowerCase()
    r = r.filter(e => e.summary?.toLowerCase().includes(q) || e.remote_addr?.includes(q))
  }
  return r
})

function fmtTime(v: string) { return dayjs(v).format('MM-DD HH:mm:ss') }
function viewRaw(r: any) { rawData.value = r; rawModal.value = true }

async function load() {
  loading.value = true
  try {
    // Fetch all recent events — for a real impl add server-side pagination
    const { data } = await api.get('/events?limit=500')
    events.value = data
  } catch {
    // endpoint not yet added — use empty list
  } finally { loading.value = false }
}
onMounted(load)
</script>

<style scoped>
.raw-pre { background: #f6f8fa; padding: 12px; border-radius: 6px; font-size:12px; max-height:400px; overflow:auto; }
</style>
