<template>
  <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl shadow-lg overflow-hidden">
    <div class="p-5 border-b border-slate-700/60 flex justify-between items-center">
      <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
        Recent Intercepted Incidents
      </h3>
      <span class="text-xs text-slate-500">Showing last {{ logs.length }} logs</span>
    </div>

    <div class="overflow-x-auto">
      <table class="w-full text-left text-sm text-slate-300">
        <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 border-b border-slate-700/60">
          <tr>
            <th class="px-4 py-3 whitespace-nowrap">Timestamp</th>
            <th class="px-4 py-3 whitespace-nowrap">Client IP</th>
            <th class="px-4 py-3 whitespace-nowrap">Main Attack Type</th>
            <th class="px-4 py-3 whitespace-nowrap">Rule ID</th>
            <th class="px-4 py-3">Request URI</th>
            <th class="px-4 py-3 text-center whitespace-nowrap">Score</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-700/40">
          <tr v-for="log in logs" :key="log.id" class="hover:bg-slate-700/30 transition-colors">
            <!-- 1. Timestamp -->
            <td class="px-4 py-3 whitespace-nowrap text-xs text-slate-400 font-mono">
              {{ log.timestamp }}
            </td>

            <!-- 2. Client IP -->
            <td class="px-4 py-3 whitespace-nowrap font-mono text-amber-400 font-medium text-xs">
              {{ log.client_ip }}
            </td>

            <!-- 3. Main Attack Type -->
            <td class="px-4 py-3 whitespace-nowrap">
              <span :class="getBadgeClass(log.attack_type)" class="px-2.5 py-1 rounded-md text-xs font-semibold border inline-block whitespace-nowrap">
                {{ log.attack_type }}
              </span>
            </td>

            <!-- 4. Rule ID -->
            <td class="px-4 py-3 whitespace-nowrap font-mono text-slate-300 text-xs font-semibold">
              {{ log.rule_id || log.rule || 'N/A' }}
            </td>

            <!-- 5. Request URI -->
            <td class="px-4 py-3 font-mono text-xs text-slate-400 max-w-[180px] truncate" :title="log.request_uri">
              {{ log.request_uri }}
            </td>

            <!-- 6. Score (Updated with Dynamic Anomaly Score Coloring) -->
            <td class="px-4 py-3 text-center whitespace-nowrap">
              <span 
                class="px-2.5 py-0.5 rounded text-xs font-bold border transition-colors" 
                :class="getScoreClass(log.anomaly_score)">
                {{ log.anomaly_score }}
              </span>
            </td>
          </tr>

          <tr v-if="logs.length === 0">
            <td colspan="6" class="text-center py-8 text-slate-500">No attack records found</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
defineProps({
  logs: {
    type: Array,
    default: () => []
  }
})

const getBadgeClass = (type) => {
  if (!type) return 'bg-slate-800 text-slate-400 border-slate-700'
  if (type.includes('SQL')) return 'bg-red-950/80 text-red-400 border-red-800/80'
  if (type.includes('XSS')) return 'bg-amber-950/80 text-amber-400 border-amber-800/80'
  if (type.includes('Command') || type.includes('RCE') || type.includes('Execution')) return 'bg-purple-950/80 text-purple-400 border-purple-800/80'
  if (type.includes('Path') || type.includes('LFI')) return 'bg-blue-950/80 text-blue-400 border-blue-800/80'
  return 'bg-slate-800 text-slate-400 border-slate-700'
}

const getScoreClass = (score) => {
  const val = Number(score) || 0;
  
  // Critical Threat (Combined Attacks / High Violation, e.g. Score 70)
  if (val >= 20) {
    return 'bg-rose-500/20 text-rose-400 border-rose-500/50 shadow-[0_0_8px_rgba(244,63,94,0.4)]';
  }
  
  // High Threat (Score 10 - 19)
  if (val >= 10) {
    return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
  }
  
  // Medium Threat (Standard Blocking Threshold: Score 5 - 9)
  if (val >= 5) {
    return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
  }
  
  // Low Threat (Score < 5)
  return 'bg-slate-700 text-slate-300 border-slate-600';
}
</script>
