<template>
  <div class="login-page">
    <div class="login-box">
      <div class="login-logo">
        <ThunderboltFilled style="font-size:26px;color:#1677ff;margin-right:8px" />
        <span class="login-title">OOBserver</span>
      </div>
      <p class="login-sub">创建账号</p>

      <a-form :model="form" @finish="submit" layout="vertical" size="middle" style="margin-top:20px">
        <a-form-item name="username" :rules="[{required:true,message:'请输入账号'}]" style="margin-bottom:12px">
          <a-input v-model:value="form.username" placeholder="账号" autocomplete="username">
            <template #prefix><UserOutlined style="color:#bfbfbf" /></template>
          </a-input>
        </a-form-item>

        <a-form-item name="email" style="margin-bottom:12px">
          <a-input v-model:value="form.email" placeholder="邮箱（选填）" autocomplete="email">
            <template #prefix><MailOutlined style="color:#bfbfbf" /></template>
          </a-input>
        </a-form-item>

        <a-form-item name="password" :rules="[{required:true,min:6,message:'密码至少6位'}]" style="margin-bottom:16px">
          <a-input-password v-model:value="form.password" placeholder="密码（至少6位）" autocomplete="new-password">
            <template #prefix><LockOutlined style="color:#bfbfbf" /></template>
          </a-input-password>
        </a-form-item>

        <a-button type="primary" html-type="submit" block :loading="loading" style="height:36px;font-size:14px">
          注 册
        </a-button>
      </a-form>

      <div class="login-footer">
        已有账号？<router-link to="/login" style="color:#1677ff">返回登录</router-link>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { UserOutlined, LockOutlined, MailOutlined, ThunderboltFilled } from '@ant-design/icons-vue'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const router = useRouter()
const loading = ref(false)
const form = ref({ username: '', email: '', password: '' })

async function submit() {
  loading.value = true
  try {
    await auth.register(form.value.username, form.value.password, form.value.email || undefined)
    router.push('/dashboard')
    message.success('注册成功')
  } catch (e: any) {
    message.error(e.response?.data?.detail || '注册失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f0f2f5;
}
.login-box {
  width: 360px;
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 4px 20px rgba(0,0,0,.08);
  padding: 36px 32px 28px;
}
.login-logo {
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 4px;
}
.login-title {
  font-size: 22px;
  font-weight: 700;
  color: #1677ff;
}
.login-sub {
  text-align: center;
  color: #bfbfbf;
  font-size: 12px;
  margin: 0;
}
.login-footer {
  text-align: center;
  margin-top: 16px;
  font-size: 12px;
  color: #8c8c8c;
}
</style>
