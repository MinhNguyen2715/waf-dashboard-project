<template>
  <div class="space-y-6">
    <!-- Header & Search Bar -->
    <div class="bg-slate-800/80 border border-slate-700/60 p-5 rounded-xl shadow-lg flex flex-col md:flex-row justify-between items-center gap-4">
      <div>
        <h2 class="text-lg font-bold text-white tracking-wide">DETAILED WAF LOGS</h2>
        <!-- <p class="text-xs text-slate-400">Search, filter, and inspect full attack payloads</p> -->
      </div>

      <div class="flex items-center space-x-3 w-full md:w-auto">
        <!-- Search Input -->
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Filter by IP, Rule ID, URI..."
          class="bg-slate-900 border border-slate-700 text-sm rounded-lg px-4 py-2 text-slate-200 focus:outline-none focus:border-blue-500 w-full md:w-64"
        />
        <!-- Refresh Button -->
        <button
          @click="fetchLogs"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center space-x-2"
        >
          <span>Refresh</span>
        </button>
      </div>
    </div>

    <!-- Main Logs Table -->
    <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl shadow-lg overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm text-slate-300">
          <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 border-b border-slate-700/60">
            <tr>
              <th class="px-4 py-3 whitespace-nowrap">ID</th>
              <th class="px-4 py-3 whitespace-nowrap">Timestamp</th>
              <th class="px-4 py-3 whitespace-nowrap">Client IP</th>
              <th class="px-4 py-3 whitespace-nowrap">Main Attack Type</th>
              <th class="px-4 py-3 whitespace-nowrap">Rule ID</th>
              <th class="px-4 py-3">Request URI</th>
              <th class="px-4 py-3 text-center whitespace-nowrap">Score</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-700/40">
<tr
  v-for="log in paginatedLogs"
  :key="log.id"
  @click="openModal(log)"
  class="hover:bg-slate-700/50 cursor-pointer transition-colors"
>
  <td class="px-4 py-3 font-mono text-xs text-slate-500">#{{ log.id }}</td>
  
  <!-- 1. Timestamp (Đã cắt bỏ thứ) -->
  <td class="px-4 py-3 whitespace-nowrap text-xs text-slate-400 font-mono">
    {{ formatTimestamp(log.timestamp) }}
  </td>

  <td class="px-4 py-3 font-mono text-amber-400 font-medium text-xs whitespace-nowrap">
    {{ log.client_ip }}
  </td>

  <!-- 2. Main Attack Type (Lấy nhãn SecBERT nếu bị AI chặn) -->
  <td class="px-4 py-3 whitespace-nowrap">
    <span :class="getBadgeClass(getMainAttackType(log))" class="px-2.5 py-1 rounded-md text-xs font-semibold border inline-block whitespace-nowrap">
      {{ getMainAttackType(log) }}
    </span>
  </td>

  <!-- 3. Rule ID (Hiển thị thẻ #SecBERT màu tím nếu AI chặn hoặc thẻ #RuleID) -->
  <td class="px-4 py-3 font-mono text-xs max-w-[240px]">
    <div class="flex flex-wrap gap-1.5 items-center">
      <span 
        v-for="(tag, idx) in getRuleTags(log)" 
        :key="idx"
        :class="tag === 'SecBERT' 
          ? 'text-purple-300 bg-purple-950/90 border-purple-700/80 shadow-[0_0_8px_rgba(168,85,247,0.3)]' 
          : 'text-slate-200 bg-slate-900/90 border-slate-700/80'"
        class="px-2 py-0.5 rounded border text-[11px] font-semibold font-mono inline-block whitespace-nowrap"
      >
        #{{ tag }}
      </span>
    </div>
  </td>

  <td class="px-4 py-3 font-mono text-xs text-slate-400 max-w-md truncate" :title="log.request_uri">
    {{ log.request_uri }}
  </td>
  
  <td class="px-4 py-3 text-center whitespace-nowrap">
    <span
      class="px-2.5 py-0.5 rounded text-xs font-bold border transition-colors"
      :class="getScoreClass(log.anomaly_score)">
      {{ log.anomaly_score }}
    </span>
  </td>
</tr>

            <tr v-if="filteredLogs.length === 0">
              <td colspan="7" class="text-center py-12 text-slate-500">No matching security logs found</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

<div 
    v-if="filteredLogs.length > 0" 
    class="px-6 py-3 bg-slate-900/50 border-t border-slate-700/60 flex flex-col sm:flex-row justify-between items-center gap-4 text-xs text-slate-400"
  >
    <div>
      Showing <span class="font-semibold text-white">{{ startIndex + 1 }}</span> to 
      <span class="font-semibold text-white">{{ endIndex }}</span> of 
      <span class="font-semibold text-white">{{ filteredLogs.length }}</span> logs
    </div>

    <div class="flex items-center space-x-2">
      <button
        @click="currentPage--"
        :disabled="currentPage === 1"
        class="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors text-white font-medium"
      >
        Previous
      </button>

      <span class="px-3 py-1.5 font-mono text-slate-300">
        Page {{ currentPage }} of {{ totalPages }}
      </span>

      <button
        @click="currentPage++"
        :disabled="currentPage >= totalPages"
        class="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors text-white font-medium"
      >
        Next
      </button>
    </div>
  </div>
</div>

    <!-- Modal Popup Chi Tiết Log -->
    <div 
      v-if="selectedLog" 
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      @click.self="closeModal"
    >
      <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-2xl w-full overflow-hidden animate-in fade-in zoom-in duration-150">
        <!-- Modal Header -->
        <div class="px-6 py-4 border-b border-slate-700 flex justify-between items-center bg-slate-900/50">
          <div class="flex items-center space-x-3">
            <h3 class="text-base font-bold text-white">Incident Details</h3>
            <span class="text-xs font-mono text-slate-400">#{{ selectedLog.id }}</span>
          </div>
          <button @click="closeModal" class="text-slate-400 hover:text-white transition-colors text-lg font-bold">
            &times;
          </button>
        </div>

        <!-- Modal Body -->
        <div class="p-6 space-y-4 max-h-[75vh] overflow-y-auto">
          <div class="grid grid-cols-2 gap-4 text-xs">
            <div>
		<span class="text-slate-400 block uppercase font-medium text-sm">Timestamp</span>
  		<span class="text-slate-200 font-mono font-semibold text-sm">{{ formatTimestamp(selectedLog.timestamp) }}</span>
	</div>
<div>
  <span class="text-slate-400 block uppercase font-medium text-sm">Client IP Address</span>
  <span class="text-amber-400 font-mono font-semibold text-sm">{{ selectedLog.client_ip }}</span>
</div>

<!-- Detected Attack Categories -->
<div class="col-span-2">
  <span class="text-slate-400 block uppercase font-medium text-sm mb-1">Detected Attack Categories</span>
  <div class="flex flex-wrap gap-1.5">
    <span
      v-for="cat in getAllAttackTypes(selectedLog)"
      :key="cat"
      :class="getBadgeClass(cat)"
      class="px-2.5 py-1 rounded text-sm font-semibold border inline-block"
    >
      {{ cat }}
    </span>
  </div>
</div>

<!-- Triggered Rules List -->
<div class="col-span-2">
  <span class="text-slate-400 block uppercase font-medium text-sm mb-1">Triggered Rules List</span>
  <div class="flex flex-wrap gap-1.5">
    <span
      v-for="(rule, idx) in getRuleTags(selectedLog)"
      :key="idx"
      :class="rule === 'SecBERT' 
        ? 'text-purple-300 bg-purple-950/90 border-purple-700/80 shadow-[0_0_8px_rgba(168,85,247,0.3)]' 
        : 'text-amber-300 bg-amber-950/40 border-amber-700/60'"
      class="px-2 py-0.5 font-mono font-bold rounded text-sm border"
    >
      {{ rule === 'SecBERT' ? 'SecBERT' : 'Rule #' + rule }}
    </span>
  </div>
</div>
            <div>
              <span class="text-slate-400 block uppercase font-medium text-sm">Anomaly Score</span>
              <span :class="getScoreClass(selectedLog.anomaly_score)" class="px-2.5 py-0.5 rounded text-sm font-bold border inline-block mt-1">
                {{ selectedLog.anomaly_score }}
              </span>
            </div>
          </div>

          <!-- Request URI Payload -->
          <div class="pt-2">
            <span class="text-xs text-slate-400 block uppercase font-medium text-sm mb-1">Full Request Payload / URI</span>
            <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-sm text-rose-300 break-all whitespace-pre-wrap select-all">
              {{ selectedLog.request_uri }}
            </div>
          </div>
        </div>

        <!-- Modal Footer -->
        <div class="px-6 py-3 border-t border-slate-700 bg-slate-900/50 flex justify-end">
          <button 
            @click="closeModal"
            class="px-4 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-xs font-medium rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>

</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'

const logs = ref([])
const searchQuery = ref('')
const selectedLog = ref(null)

const currentPage = ref(1)
const pageSize = ref(10)

const fetchLogs = async () => {
  try {
    const res = await fetch('http://127.0.0.1:8000/api/logs/recent?limit=50')
    if (res.ok) {
      logs.value = await res.json()
    }
  } catch (err) {
    console.error('Failed to fetch logs:', err)
  }
}

const formatTimestamp = (ts) => {
  if (!ts) return 'N/A'
  return ts.replace(/^[A-Za-z]{3}\s+/, '')
}

const getMainAttackType = (log) => {
  if (!log) return 'Normal'

  const blocker = (log.blocked_by || log.blockedBy || '').toLowerCase()
  let rawType = ''

  if (blocker.includes('secbert') || blocker.includes('ai')) {
    rawType = log.ai_attack_type || log.aiAttackType || log.attack_type || 'Normal'
  } else {
    rawType = log.attack_type || 'Normal'
  }

  return rawType.replace(/^\d+\s*-\s*/, '').trim()
}

const getAllAttackTypes = (log) => {
  if (!log) return ['Normal']

  const blocker = (log.blocked_by || log.blockedBy || '').toLowerCase()

  if (blocker.includes('secbert') || blocker.includes('ai')) {
    const aiType = log.ai_attack_type || log.aiAttackType || log.attack_type || 'Normal'
    return [aiType.replace(/^\d+\s*-\s*/, '').trim()]
  }

  if (Array.isArray(log.all_attack_types) && log.all_attack_types.length > 0) {
    return log.all_attack_types.map(t => t.replace(/^\d+\s*-\s*/, '').trim())
  }

  return [getMainAttackType(log)]
}

const getRuleTags = (log) => {
  if (!log) return ['N/A']

  const blocker = (log.blocked_by || log.blockedBy || '').toLowerCase()
  const aiType = (log.ai_attack_type || log.aiAttackType || '').toLowerCase()

  if (
    blocker.includes('secbert') || 
    blocker.includes('ai') || 
    (aiType && !aiType.includes('normal') && !aiType.includes('skipped') && !log.matched_rules?.length)
  ) {
    return ['SecBERT']
  }

  let rulesRaw = log.rule_id || log.rule || log.matched_rules || log.matchedRules

  if (Array.isArray(rulesRaw)) {
    return rulesRaw.length > 0 ? Array.from(new Set(rulesRaw)) : ['N/A']
  }

  if (typeof rulesRaw === 'string' && rulesRaw.trim() !== '') {
    const list = rulesRaw.split(',').map(r => r.trim()).filter(r => r && r !== 'N/A')
    return list.length > 0 ? Array.from(new Set(list)) : ['N/A']
  }

  return ['N/A']
}

const filteredLogs = computed(() => {
  if (!searchQuery.value) return logs.value
  const query = searchQuery.value.toLowerCase()
  return logs.value.filter(log => {
    const mainType = getMainAttackType(log).toLowerCase()
    const rules = getRuleTags(log).join(' ').toLowerCase()
    const ip = (log.client_ip || '').toLowerCase()
    const uri = (log.request_uri || log.uri || '').toLowerCase()
    return ip.includes(query) || mainType.includes(query) || rules.includes(query) || uri.includes(query)
  })
})

const openModal = (log) => {
  selectedLog.value = log
}

const closeModal = () => {
  selectedLog.value = null
}

const totalPages = computed(() => {
  return Math.ceil(filteredLogs.value.length / pageSize.value) || 1
})

const startIndex = computed(() => {
  return (currentPage.value - 1) * pageSize.value
})

const endIndex = computed(() => {
  return Math.min(startIndex.value + pageSize.value, filteredLogs.value.length)
})

const paginatedLogs = computed(() => {
  return filteredLogs.value.slice(startIndex.value, endIndex.value)
})

watch(searchQuery, () => {
  currentPage.value = 1
})

const getBadgeClass = (type) => {
  if (!type) return 'bg-slate-800 text-slate-400 border-slate-700'

  const t = type.toLowerCase()

  if (t.includes('combined') || t.includes('mixed')) {
    return 'bg-fuchsia-950/80 text-fuchsia-300 border-fuchsia-700/80 shadow-[0_0_8px_rgba(217,70,239,0.2)]'
  }
  if (t.includes('code injection') || t.includes('sql')) {
    return 'bg-red-950/80 text-red-400 border-red-800/80'
  }
  if (t.includes('xss') || t.includes('scripting')) {
    return 'bg-amber-950/80 text-amber-400 border-amber-800/80'
  }
  if (t.includes('rce') || t.includes('command') || t.includes('execution')) {
    return 'bg-purple-950/80 text-purple-400 border-purple-800/80'
  }
  if (t.includes('path traversal') || t.includes('path') || t.includes('lfi') || t.includes('rfi')) {
    return 'bg-blue-950/80 text-blue-400 border-blue-800/80'
  }
  if (t.includes('input data manipulation') || t.includes('input data') || t.includes('php')) {
    return 'bg-indigo-950/80 text-indigo-300 border-indigo-700/80'
  }
  if (t.includes('scanning') || t.includes('vulnerable') || t.includes('scanner')) {
    return 'bg-emerald-950/80 text-emerald-400 border-emerald-800/80'
  }
  if (
    t.includes('fake') || 
    t.includes('source of data') || 
    t.includes('response splitting') || 
    t.includes('protocol')
  ) {
    return 'bg-orange-950/80 text-orange-400 border-orange-800/80'
  }
  if (t.includes('normal')) {
    return 'bg-slate-800 text-slate-400 border-slate-700'
  }

  return 'bg-slate-800 text-slate-300 border-slate-700'
}

const getScoreClass = (score) => {
  const val = Number(score) || 0
  if (val >= 20) return 'bg-rose-500/20 text-rose-400 border-rose-500/50 shadow-[0_0_8px_rgba(244,63,94,0.4)]'
  if (val >= 10) return 'bg-orange-500/20 text-orange-400 border-orange-500/50'
  if (val >= 5)  return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50'
  return 'bg-slate-700 text-slate-300 border-slate-600'
}

onMounted(() => {
  fetchLogs()
})
</script>
