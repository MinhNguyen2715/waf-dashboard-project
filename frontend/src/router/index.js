import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import LogsView from '../views/LogsView.vue'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard
  },
  {
    path: '/logs',
    name: 'Logs',
    component: LogsView
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
