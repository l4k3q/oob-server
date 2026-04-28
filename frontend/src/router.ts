import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login',    component: () => import('./views/Login.vue'),    meta: { public: true } },
    { path: '/register', component: () => import('./views/Register.vue'), meta: { public: true } },
    {
      path: '/',
      component: () => import('./views/Layout.vue'),
      children: [
        { path: '', redirect: '/dashboard' },
        { path: 'dashboard',      component: () => import('./views/Dashboard.vue') },
        { path: 'projects',       component: () => import('./views/Projects.vue') },
        { path: 'tokens',         component: () => import('./views/Tokens.vue') },
        { path: 'payload-builder',component: () => import('./views/PayloadBuilder.vue') },
        { path: 'memshell-lab',   component: () => import('./views/MemshellLab.vue') },
        { path: 'compile-lab',    component: () => import('./views/CompileLab.vue') },
        { path: 'agents',         component: () => import('./views/Agents.vue') },
        { path: 'events',         component: () => import('./views/Events.vue') },
      ]
    },
    { path: '/:p(.*)', redirect: '/' }
  ]
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.token) return '/login'
})

export default router
