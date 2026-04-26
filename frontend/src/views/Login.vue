<template>
  <div class="login-page">
    <div class="login-box">
      <!-- Logo -->
      <div class="login-logo">
        <ThunderboltFilled style="font-size:26px;color:#1677ff;margin-right:8px" />
        <span class="login-title">OOBserver</span>
      </div>
      <p class="login-sub">OOB Exploitation Platform</p>

      <!-- Form -->
      <a-form :model="form" @finish="submit" layout="vertical" size="middle" style="margin-top:20px">
        <a-form-item name="username" :rules="[{required:true,message:'请输入账号'}]" style="margin-bottom:12px">
          <a-input
            v-model:value="form.username"
            placeholder="账号"
            autocomplete="username"
          >
            <template #prefix><UserOutlined style="color:#bfbfbf" /></template>
          </a-input>
        </a-form-item>

        <a-form-item name="password" :rules="[{required:true,message:'请输入密码'}]" style="margin-bottom:16px">
          <a-input-password
            v-model:value="form.password"
            placeholder="密码"
            autocomplete="current-password"
          >
            <template #prefix><LockOutlined style="color:#bfbfbf" /></template>
          </a-input-password>
        </a-form-item>

        <a-button
          type="primary"
          html-type="submit"
          block
          :loading="loading"
          style="height:36px;font-size:14px"
        >
          登 录
        </a-button>
      </a-form>

      <div class="login-footer">
        还没有账号？
        <a @click.prevent="goRegister" href="/register" style="color:#1677ff;cursor:pointer">
          立即注册（首位用户自动成为管理员）
        </a>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { UserOutlined, LockOutlined, ThunderboltFilled } from '@ant-design/icons-vue'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const router = useRouter()
const loading = ref(false)
const form = ref({ username: '', password: '' })

function goRegister() {
  router.push('/register')
}

async function submit() {
  loading.value = true
  try {
    await auth.login(form.value.username, form.value.password)
    router.push('/dashboard')
  } catch (e: any) {
    if (e.response?.status === 401) {
      try {
        await auth.register(form.value.username, form.value.password)
        router.push('/dashboard')
        message.success('注册成功，已自动登录')
      } catch (e2: any) {
        message.error(e2.response?.data?.detail || '账号或密码错误')
      }
    } else {
      message.error(e.response?.data?.detail || '登录失败')
    }
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
  margin: 0 0 0;
}
.login-footer {
  text-align: center;
  margin-top: 16px;
  font-size: 12px;
  color: #8c8c8c;
}
</style>
