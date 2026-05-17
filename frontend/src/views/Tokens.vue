<template>
  <a-card :bordered="false">
    <template #title>Token 管理</template>
    <template #extra>
      <a-space>
        <a-select v-model:value="filterProject" style="width:160px" allow-clear placeholder="筛选项目"
                  @change="load">
          <a-select-option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</a-select-option>
        </a-select>
        <a-button type="primary" @click="showCreate=true"><PlusOutlined />新建 Token</a-button>
      </a-space>
    </template>

    <a-table :data-source="tokens" :columns="columns" :loading="loading" row-key="id" size="small">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key==='token'">
          <a-tag color="blue" class="font-mono">{{ record.token }}</a-tag>
        </template>
        <template v-if="column.key==='intent'">
          <a-tag :color="INTENT_COLOR[record.intent]||'default'">{{ record.intent }}</a-tag>
        </template>
        <template v-if="column.key==='protocols'">
          <a-tag v-for="p in record.protocols" :key="p" size="small" style="margin:2px">{{ p }}</a-tag>
        </template>
        <template v-if="column.key==='created_at'">{{ fmtDate(record.created_at) }}</template>
        <template v-if="column.key==='action'">
          <a-space>
            <a-button size="small" @click="showUrls(record)">URLs</a-button>
            <a-button size="small" @click="showEvts(record)">命中</a-button>
            <a-popconfirm title="确认删除?" @confirm="del(record)" ok-type="danger" ok-text="删除">
              <a-button size="small" danger>删除</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </template>
    </a-table>
  </a-card>

  <!-- Create modal -->
  <a-modal v-model:open="showCreate" title="新建 Token" @ok="create" :confirm-loading="saving">
    <a-form :model="form" layout="vertical">
      <a-form-item label="项目" required>
        <a-select v-model:value="form.project_id" style="width:100%">
          <a-select-option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</a-select-option>
        </a-select>
      </a-form-item>
      <a-form-item label="标签">
        <a-input v-model:value="form.label" placeholder="如：log4j-test" />
      </a-form-item>
      <a-form-item label="协议">
        <a-checkbox-group v-model:value="form.protocols">
          <a-checkbox v-for="p in ['http','ldap','rmi','tcp','dns']" :key="p" :value="p">{{ p }}</a-checkbox>
        </a-checkbox-group>
      </a-form-item>
      <a-form-item label="意图">
        <a-select v-model:value="form.intent" style="width:100%">
          <a-select-option value="record">record — 仅记录</a-select-option>
          <a-select-option value="jndi">jndi — LDAP/RMI 重绑</a-select-option>
          <a-select-option value="memshell">memshell — 投递内存马</a-select-option>
          <a-select-option value="jndi_serialize">jndi_serialize - LDAP javaSerializedData</a-select-option>
        </a-select>
      </a-form-item>
    </a-form>
  </a-modal>

  <!-- URLs drawer -->
  <a-drawer v-model:open="urlDrawer.visible" :title="`回连地址 — ${urlDrawer.token}`" width="540">
    <div v-for="(v, k) in urlDrawer.urls" :key="k" class="mb-3">
      <div class="text-gray-500 text-xs mb-1">{{ k }}</div>
      <a-input-group compact>
        <a-input :value="String(v)" read-only style="width:calc(100%-72px)" class="font-mono text-xs" />
        <a-button type="primary" @click="copy(String(v))">复制</a-button>
      </a-input-group>
    </div>
  </a-drawer>

  <!-- Events drawer -->
  <a-drawer v-model:open="evtDrawer.visible" :title="`命中记录 — ${evtDrawer.token}`" width="700">
    <a-table :data-source="evtDrawer.events" size="small" row-key="id" :pagination="{pageSize:50}">
      <a-table-column title="协议" dataIndex="protocol" :width="80">
        <template #default="{text}"><a-tag :color="PROTO_COLOR[text]||'default'">{{ text }}</a-tag></template>
      </a-table-column>
      <a-table-column title="来源" dataIndex="remote_addr" :width="140" />
      <a-table-column title="摘要" dataIndex="summary" />
      <a-table-column title="时间" dataIndex="created_at" :width="160">
        <template #default="{text}">{{ fmtDate(text) }}</template>
      </a-table-column>
    </a-table>
  </a-drawer>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { message } from 'ant-design-vue'
import { PlusOutlined } from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import { listTokens, createToken, deleteToken, tokenEvents, listProjects } from '../api'

const route = useRoute()
const tokens = ref<any[]>([])
const projects = ref<any[]>([])
const loading = ref(false)
const saving = ref(false)
const showCreate = ref(false)
const filterProject = ref<number | undefined>()
const form = ref({ project_id: null as any, label:'', protocols:['http','ldap','rmi','tcp'], intent:'record' })
const urlDrawer = ref({ visible:false, token:'', urls:{} as any })
const evtDrawer = ref({ visible:false, token:'', events:[] as any[] })

const INTENT_COLOR: Record<string,string> = { record:'default', jndi:'orange', jndi_reference:'cyan', jndi_serialize:'purple', memshell:'red', serialize:'purple' }
const PROTO_COLOR: Record<string,string> = { http:'green', ldap:'orange', rmi:'red', tcp:'blue', dns:'purple' }

const columns = [
  { title: 'Token', key:'token', dataIndex:'token', width:140 },
  { title: '标签', dataIndex:'label' },
  { title: '意图', key:'intent', dataIndex:'intent', width:100 },
  { title: '协议', key:'protocols', dataIndex:'protocols', width:180 },
  { title: '创建时间', key:'created_at', dataIndex:'created_at', width:160 },
  { title: '操作', key:'action', width:180 },
]

function fmtDate(v: string) { return dayjs(v).format('MM-DD HH:mm:ss') }
function copy(v: string) { navigator.clipboard.writeText(v); message.success('已复制') }

async function load() {
  loading.value = true
  try {
    const pid = filterProject.value || (route.query.project_id ? Number(route.query.project_id) : undefined)
    tokens.value = (await listTokens(pid)).data
  } finally { loading.value = false }
}

async function loadProjects() {
  projects.value = (await listProjects()).data
  if (projects.value.length && !form.value.project_id)
    form.value.project_id = projects.value[0].id
}

async function create() {
  saving.value = true
  try {
    await createToken({ ...form.value })
    showCreate.value = false
    await load()
    message.success('创建成功')
  } catch(e:any) { message.error(e.response?.data?.detail || '创建失败') }
  finally { saving.value = false }
}

async function del(r: any) {
  await deleteToken(r.token)
  await load()
}

function showUrls(r: any) { urlDrawer.value = { visible:true, token:r.token, urls:r.urls } }
async function showEvts(r: any) {
  const { data } = await tokenEvents(r.token)
  evtDrawer.value = { visible:true, token:r.token, events:data }
}

onMounted(() => { load(); loadProjects() })
</script>
