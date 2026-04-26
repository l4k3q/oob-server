import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('oobx_token')
  if (token) cfg.headers['Authorization'] = `Bearer ${token}`
  return cfg
})

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('oobx_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api

// Auth
export const authLogin = (username: string, password: string) =>
  api.post('/auth/login', new URLSearchParams({ username, password }))
export const authRegister = (data: { username: string; password: string; email?: string }) =>
  api.post('/auth/register', data)
export const authMe = () => api.get('/auth/me')

// Projects
export const listProjects = () => api.get('/projects')
export const createProject = (data: { name: string; description?: string }) =>
  api.post('/projects', data)
export const deleteProject = (id: number) => api.delete(`/projects/${id}`)

// Tokens
export const listTokens = (projectId?: number) =>
  api.get('/tokens', { params: projectId ? { project_id: projectId } : {} })
export const createToken = (data: any) => api.post('/tokens', data)
export const getToken = (token: string) => api.get(`/tokens/${token}`)
export const tokenEvents = (token: string) => api.get(`/tokens/${token}/events`)
export const deleteToken = (token: string) => api.delete(`/tokens/${token}`)

// Payloads
export const getPayloadCatalog = (category?: string, q?: string) =>
  api.get('/payloads/catalog', { params: { category, q } })
export const generatePayload = (data: any) => api.post('/payloads/generate', data)

// Memshells
export const getMemshellCatalog = () => api.get('/memshells/catalog')
export const generateMemshell = (data: any) => api.post('/memshells/generate', data)

// Rebind
export const setRebind = (token: string, data: any) => api.post(`/rebind/${token}/set`, data)
export const clearRebind = (token: string) => api.delete(`/rebind/${token}/clear`)

// C2 / Agents
export const listAgents = () => api.get('/c2/agents')
export const sendCommand = (agentId: string, cmd: string) =>
  api.post(`/c2/agents/${agentId}/cmd`, { cmd })
export const listCommands = (agentId: string) => api.get(`/c2/agents/${agentId}/commands`)
