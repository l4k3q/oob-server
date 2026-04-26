<template>
  <a-card :bordered="false">
    <template #title>项目管理</template>
    <template #extra>
      <a-button type="primary" @click="showCreate=true"><PlusOutlined /> 新建项目</a-button>
    </template>

    <a-table :data-source="projects" :columns="columns" :loading="loading" row-key="id" size="small">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key==='created_at'">{{ fmtDate(record.created_at) }}</template>
        <template v-if="column.key==='action'">
          <a-space>
            <a-button size="small" type="link" @click="goTokens(record)">Tokens</a-button>
            <a-popconfirm title="确认删除?" @confirm="del(record)" ok-text="删除" ok-type="danger">
              <a-button size="small" type="link" danger>删除</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </template>
    </a-table>
  </a-card>

  <a-modal v-model:open="showCreate" title="新建项目" @ok="create" :confirm-loading="saving">
    <a-form :model="form" layout="vertical">
      <a-form-item label="项目名称" required>
        <a-input v-model:value="form.name" />
      </a-form-item>
      <a-form-item label="描述">
        <a-textarea v-model:value="form.description" :rows="3" />
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { PlusOutlined } from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import { listProjects, createProject, deleteProject } from '../api'

const router = useRouter()
const projects = ref<any[]>([])
const loading = ref(false)
const saving = ref(false)
const showCreate = ref(false)
const form = ref({ name:'', description:'' })

const columns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '名称', dataIndex: 'name' },
  { title: '描述', dataIndex: 'description' },
  { title: '创建时间', key: 'created_at', dataIndex: 'created_at', width: 180 },
  { title: '操作', key: 'action', width: 140 },
]

function fmtDate(v: string) { return dayjs(v).format('YYYY-MM-DD HH:mm') }
function goTokens(r: any) { router.push(`/tokens?project_id=${r.id}`) }

async function load() {
  loading.value = true
  try { projects.value = (await listProjects()).data }
  finally { loading.value = false }
}

async function create() {
  saving.value = true
  try {
    await createProject({ name: form.value.name, description: form.value.description || undefined })
    showCreate.value = false
    form.value = { name:'', description:'' }
    await load()
    message.success('创建成功')
  } catch(e:any) { message.error(e.response?.data?.detail || '创建失败') }
  finally { saving.value = false }
}

async function del(r: any) {
  await deleteProject(r.id)
  await load()
  message.success('已删除')
}
onMounted(load)
</script>
