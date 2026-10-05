<template>
  <div class="space-y-6">
    <!-- 1. Top KPI Stats Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <!-- Total Threats Blocked -->
      <StatCard title="Total Threats Blocked" :value="stats.total_blocked" valueClass="text-red-500" iconBgClass="bg-red-500/10 text-red-400">
        <template #icon>
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        </template>
      </StatCard>

      <!-- Top Attacker IP -->
      <StatCard title="Top Attacker IP" :value="stats.top_attacker_ip" :subtitle="`${stats.top_ip_count} malicious requests`" valueClass="text-amber-400 text-2xl truncate" iconBgClass="bg-amber-500/10 text-amber-400">
        <template #icon>
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </template>
      </StatCard>

      <!-- Most Frequent Attack Type -->
      <StatCard title="Most Frequent Attack" :value="stats.most_frequent_attack" valueClass="text-yellow-400 text-xl truncate" iconBgClass="bg-yellow-500/10 text-yellow-400">
        <template #icon>
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
        </template>
      </StatCard>

      <!-- High Threat Level Count -->
      <StatCard title="High Threat Level Count" :value="stats.high_threat_count" subtitle="Anomaly Score ≥ 8" valueClass="text-purple-400" iconBgClass="bg-purple-500/10 text-purple-400">
        <template #icon>
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"/></svg>
        </template>
      </StatCard>
    </div>

    <!-- 2. Charts & Tables Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div class="lg:col-span-1">
        <AttackChart :distribution="stats.attack_distribution || {}" />
      </div>
      <div class="lg:col-span-2">
        <IncidentTable :logs="recentLogs" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import StatCard from '../components/StatCard.vue'
import AttackChart from '../components/AttackChart.vue'
import IncidentTable from '../components/IncidentTable.vue'

const stats = ref({
  total_blocked: 0,
  top_attacker_ip: 'N/A',
  top_ip_count: 0,
  most_frequent_attack: 'None',
  high_threat_count: 0,
  attack_distribution: {}
})

const recentLogs = ref([])
let timer = null

const fetchData = async () => {
  try {
    const [resStats, resLogs] = await Promise.all([
      fetch('http://127.0.0.1:8000/api/stats/overview'),
      fetch('http://127.0.0.1:8000/api/logs/recent')
    ])
    if (resStats.ok) stats.value = await resStats.json()
    if (resLogs.ok) recentLogs.value = await resLogs.json()
  } catch (err) {
    console.error('API Error:', err)
  }
}

onMounted(() => {
  fetchData()
  timer = setInterval(fetchData, 2000) // Renew each 2s
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>
