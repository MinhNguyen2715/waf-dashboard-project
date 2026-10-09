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
	    <th class="px-4 py-3 text-center whitespace-nowrap">Score</th>
            <th class="px-4 py-3 whitespace-nowrap w-32">Rule ID</th>
            <th class="px-4 py-3 w-48">Request URI</th>
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

		<td class="px-4 py-3 text-center whitespace-nowrap">
              <span
                class="px-2.5 py-0.5 rounded text-xs font-bold border transition-colors"
                :class="getScoreClass(log.anomaly_score)">
                {{ log.anomaly_score }}
              </span>
            </td>

            <!-- 5. Rule ID (Fix độ rộng max-w-[130px]) -->
            <td class="px-4 py-3 font-mono text-slate-300 text-xs font-semibold max-w-[130px] truncate" :title="log.rule_id || log.rule">
              {{ log.rule_id || log.rule || 'N/A' }}
            </td>

            <!-- 6. Request URI (Fix độ rộng max-w-[200px]) -->
            <td class="px-4 py-3 font-mono text-xs text-slate-400 max-w-[200px] truncate" :title="log.request_uri">
              {{ log.request_uri }}
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
  
  const t = type.toLowerCase()

  // 1. Tấn công gộp (Combined / Mixed) -> Tím Fuchsia nổi bật
  if (t.includes('combined') || t.includes('mixed')) {
    return 'bg-fuchsia-950/80 text-fuchsia-300 border-fuchsia-700/80 shadow-[0_0_8px_rgba(217,70,239,0.2)]'
  }
  
  // 2. SQL Injection -> Đỏ thẫm
  if (t.includes('sql')) {
    return 'bg-red-950/80 text-red-400 border-red-800/80'
  }
  
  // 3. Cross-Site Scripting (XSS) -> Vàng Cam (Amber)
  if (t.includes('xss') || t.includes('scripting')) {
    return 'bg-amber-950/80 text-amber-400 border-amber-800/80'
  }
  
  // 4. Remote Code Execution (RCE) / Command Injection -> Tím Đậm (Purple)
  if (t.includes('rce') || t.includes('command') || t.includes('execution')) {
    return 'bg-purple-950/80 text-purple-400 border-purple-800/80'
  }
  
  // 5. Path Traversal / LFI / RFI -> Xanh Dương (Blue)
  if (t.includes('path') || t.includes('traversal') || t.includes('lfi') || t.includes('rfi')) {
    return 'bg-blue-950/80 text-blue-400 border-blue-800/80'
  }
  
  // 6. PHP Injection -> Tím Chàm (Indigo)
  if (t.includes('php')) {
    return 'bg-indigo-950/80 text-indigo-300 border-indigo-700/80'
  }
  
  // 7. Security Scanner / Dò quét -> Xanh Lá (Emerald)
  if (t.includes('scanner') || t.includes('detected')) {
    return 'bg-emerald-950/80 text-emerald-400 border-emerald-800/80'
  }
  
  // 8. Protocol Violation -> Cam Đậm (Orange)
  if (t.includes('protocol') || t.includes('violation')) {
    return 'bg-orange-950/80 text-orange-400 border-orange-800/80'
  }

  // Fallback mặc định
  return 'bg-slate-800 text-slate-300 border-slate-700'
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
