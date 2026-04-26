import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authLogin, authRegister, authMe } from '../api'

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(localStorage.getItem('oobx_token'))
  const user = ref<any>(null)

  const isLoggedIn = computed(() => !!token.value)

  async function login(username: string, password: string) {
    const { data } = await authLogin(username, password)
    token.value = data.access_token
    localStorage.setItem('oobx_token', data.access_token)
    await fetchMe()
  }

  async function register(username: string, password: string, email?: string) {
    await authRegister({ username, password, email })
    await login(username, password)
  }

  async function fetchMe() {
    try {
      const { data } = await authMe()
      user.value = data
    } catch {
      logout()
    }
  }

  function logout() {
    token.value = null
    user.value = null
    localStorage.removeItem('oobx_token')
  }

  if (token.value) fetchMe()

  return { token, user, isLoggedIn, login, register, logout, fetchMe }
})
