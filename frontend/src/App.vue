<template>
  <div class="min-h-screen bg-[#0f172a] text-slate-100 p-6">
    <!-- Header -->
    <header class="flex justify-between items-center pb-6 mb-6 border-b border-slate-700">
      <div class="flex items-center space-x-3">
        <ShieldAlert class="w-9 h-9 text-sky-400" />
        <div>
          <h1 class="text-2xl font-bold tracking-wide">WAF SECURITY DASHBOARD</h1>
          <!--
	  <p class="text-xs text-slate-400">Nginx + ModSecurity v3 Real-Time Monitoring</p>
	  -->      
	</div>
      </div>
      <div class="flex items-center space-x-2 bg-slate-800 px-3 py-1.5 rounded-full border border-slate-700">
        <span class="relative flex h-3 w-3">
          <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span class="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
        </span>
        <span class="text-xs font-medium text-emerald-400">SYSTEM ACTIVE</span>
      </div>
    </header>

    <!-- Stat Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
      <div class="bg-[#1e293b] p-5 rounded-xl border border-slate-700 shadow-lg">
        <div class="flex justify-between items-center">
          <span class="text-slate-400 text-lg font-medium">Total Threats Blocked</span>
          <ShieldX class="w-6 h-6 text-rose-500" />
        </div>
        <div class="text-3xl font-extrabold mt-2 text-rose-400">{{ stats.total_blocked || 0 }}</div>
      </div>

      <div class="bg-[#1e293b] p-5 rounded-xl border border-slate-700 shadow-lg">
        <div class="flex justify-between items-center">
          <span class="text-slate-400 text-lg font-medium">Top Attacker IP</span>
          <Activity class="w-6 h-6 text-amber-500" />
        </div>
        <div class="text-2xl font-bold mt-2 text-amber-400">
          {{ stats.top_ips?.[0]?.ip || 'N/A' }}
        </div>
        <div class="text-xs text-slate-500 mt-1" v-if="stats.top_ips?.[0]">
          {{ stats.top_ips[0].count }} malicious requests
        </div>
      </div>

      <div class="bg-[#1e293b] p-5 rounded-xl border border-slate-700 shadow-lg">
        <div class="flex justify-between items-center">
          <span class="text-slate-400 text-lg font-medium">SQLi & XSS Threats</span>
          <AlertTriangle class="w-6 h-6 text-yellow-500" />
        </div>
        <div class="text-3xl font-extrabold mt-2 text-yellow-400">
          {{ getCategoryCount(['SQL Injection (SQLi)', 'Cross-Site Scripting (XSS)']) }}
        </div>
      </div>

      <div class="bg-[#1e293b] p-5 rounded-xl border border-slate-700 shadow-lg">
        <div class="flex justify-between items-center">
          <span class="text-slate-400 text-lg font-medium">RCE & LFI Threats</span>
          <Terminal class="w-6 h-6 text-purple-500" />
        </div>
        <div class="text-3xl font-extrabold mt-2 text-purple-400">
          {{ getCategoryCount(['Command Injection', 'Path Traversal / LFI']) }}
        </div>
      </div>
    </div>

    <!-- Charts & Analytics Section -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
      <!-- Doughnut Chart -->
      <div class="bg-[#1e293b] p-6 rounded-xl border border-slate-700 shadow-lg">
        <h2 class="text-xl font-semibold mb-4 text-white">Attack Vectors Distribution</h2>
        <div class="h-64 flex justify-center items-center">
          <Doughnut v-if="chartData.labels.length" :data="chartData" :options="chartOptions" />
          <span v-else class="text-slate-500 text-sm">Awaiting attack logs...</span>
        </div>
      </div>

      <!-- Top Attacker IPs Table -->
      <div class="lg:col-span-2 bg-[#1e293b] p-6 rounded-xl border border-slate-700 shadow-lg">
        <h2 class="text-xl font-semibold mb-4 text-white">Top Attacking IP Addresses</h2>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-800 text-white uppercase text-base">
              <tr>
                <th class="p-3">IP Address</th>
                <th class="p-3">Attack Count</th>
                <th class="p-3">Threat Level</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr v-for="ip in stats.top_ips" :key="ip.ip" class="hover:bg-slate-800/50">
                <td class="p-3 font-mono text-sky-400">{{ ip.ip }}</td>
                <td class="p-3 font-semibold">{{ ip.count }}</td>
                <td class="p-3">
                  <span class="px-2 py-1 bg-rose-500/20 text-rose-400 rounded text-xs font-semibold">HIGH</span>
                </td>
              </tr>
              <tr v-if="!stats.top_ips?.length">
                <td colspan="3" class="p-4 text-center text-slate-500">No attacker IPs logged yet.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Recent Logs Table -->
    <div class="bg-[#1e293b] p-6 rounded-xl border border-slate-700 shadow-lg">
      <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-semibold mb-4 text-white">Real-Time Security Event Logs</h2>
        <button @click="fetchData" class="text-base bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded border border-slate-700">
          Manual Refresh
        </button>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm text-slate-300">
          <thead class="bg-slate-800 text-white uppercase text-base">
            <tr>
              <th class="p-3">ID</th>
              <th class="p-3">Timestamp</th>
              <th class="p-3">Client IP</th>
              <th class="p-3">Attack Category</th>
              <th class="p-3">Score</th>
              <th class="p-3">Request Payload</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800">
            <tr v-for="log in recentLogs" :key="log.id" class="hover:bg-slate-800/50 transition-colors">
              <td class="p-3 text-sm font-mono text-slate-500">#{{ log.id }}</td>
              <td class="p-3 text-xm text-slate-400">{{ log.timestamp }}</td>
              <td class="p-3 font-mono text-sky-400">{{ log.client_ip }}</td>
              <td class="p-3">
                <span :class="getBadgeClass(log.attack_type)" class="px-2.5 py-1 rounded-full text-xs font-semibold">
                  {{ log.attack_type }}
                </span>
              </td>
              <td class="p-3 font-bold text-amber-400">{{ log.anomaly_score }}</td>
              <td class="p-3 font-mono text-xs text-slate-400 truncate max-w-md" :title="log.request_uri">
                {{ log.request_uri }}
              </td>
            </tr>
            <tr v-if="!recentLogs.length">
              <td colspan="6" class="p-6 text-center text-slate-500">No attack events recorded. System is secure.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { ShieldAlert, ShieldX, Activity, AlertTriangle, Terminal } from '@lucide/vue'
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js'
import { Doughnut } from 'vue-chartjs'

ChartJS.register(ArcElement, Tooltip, Legend)

const API_BASE = 'http://127.0.0.1:8000/api'

const stats = ref({ total_blocked: 0, top_ips: [], attack_types: [] })
const recentLogs = ref([])

const chartData = ref({
  labels: [],
  datasets: [{ backgroundColor: ['#f43f5e', '#3b82f6', '#eab308', '#a855f7', '#64748b'], data: [] }]
})

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' , font: { size: 13} } } }
}

const fetchData = async () => {
  try {
    const [statsRes, logsRes] = await Promise.all([
      axios.get(`${API_BASE}/stats/overview`),
      axios.get(`${API_BASE}/logs/recent`)
    ])

    stats.value = statsRes.data
    recentLogs.value = logsRes.data

    if (stats.value.attack_types?.length) {
      chartData.value = {
        labels: stats.value.attack_types.map(item => item.type),
        datasets: [{
          backgroundColor: ['#f43f5e', '#3b82f6', '#eab308', '#a855f7', '#10b981'],
          data: stats.value.attack_types.map(item => item.count)
        }]
      }
    }
  } catch (err) {
    console.error('Error fetching dashboard data:', err)
  }
}

const getCategoryCount = (types) => {
  if (!stats.value.attack_types) return 0
  return stats.value.attack_types
    .filter(item => types.includes(item.type))
    .reduce((sum, item) => sum + item.count, 0)
}

const getBadgeClass = (type) => {
  if (type.includes('SQL')) return 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
  if (type.includes('XSS')) return 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
  if (type.includes('Command')) return 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
  if (type.includes('Path')) return 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
  return 'bg-slate-700 text-slate-300'
}

let timer = null
onMounted(() => {
  fetchData()
  timer = setInterval(fetchData, 2000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>
