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
              {{ formatTimestamp(log.timestamp) }}
            </td>

            <!-- 2. Client IP -->
            <td class="px-4 py-3 whitespace-nowrap font-mono text-amber-400 font-medium text-xs">
              {{ log.client_ip }}
            </td>

            <!-- 3. Main Attack Type -->
<td class="px-4 py-3 whitespace-nowrap">
  <span 
    :style="getBadgeStyle(getMainAttackType(log))" 
    class="px-2.5 py-1 rounded-md text-xs font-semibold border inline-block whitespace-nowrap"
  >
    {{ getMainAttackType(log) }}
  </span>
</td>
		
		<td class="px-4 py-3 text-center whitespace-nowrap">             
		<span
                class="px-2.5 py-0.5 rounded text-xs font-bold border transition-colors"
                :class="getScoreClass(log.anomaly_score)">
                {{ log.anomaly_score }}
              </span>
            </td>

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
    return rulesRaw.length > 0 ? rulesRaw : ['N/A']
  }

  if (typeof rulesRaw === 'string' && rulesRaw.trim() !== '') {
    const list = rulesRaw.split(',').map(r => r.trim()).filter(r => r && r !== 'N/A')
    return list.length > 0 ? list : ['N/A']
  }

  return ['N/A']
}

const getBadgeStyle = (type) => {
  if (!type || type.toLowerCase().includes('normal')) {
    return {
      backgroundColor: 'rgba(30, 41, 59, 0.8)',
      borderColor: 'rgba(51, 65, 85, 0.8)',
      color: '#94a3b8'
    }
  }

  let hash = 0
  for (let i = 0; i < type.length; i++) {
    hash = type.charCodeAt(i) + ((hash << 5) - hash)
  }

  const hue = Math.floor(Math.abs(hash * 137.5)) % 360

  return {
    backgroundColor: `hsla(${hue}, 85%, 15%, 0.85)`, 
    borderColor: `hsla(${hue}, 85%, 45%, 0.8)`,    
    color: `hsl(${hue}, 90%, 75%)`                  
  }
}

// 5. Score Threat Level
const getScoreClass = (score) => {
  const val = Number(score) || 0
  if (val >= 20) return 'bg-rose-500/20 text-rose-400 border-rose-500/50 shadow-[0_0_8px_rgba(244,63,94,0.4)]'
  if (val >= 10) return 'bg-orange-500/20 text-orange-400 border-orange-500/50'
  if (val >= 5)  return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50'
  return 'bg-slate-700 text-slate-300 border-slate-600'
}
</script>
