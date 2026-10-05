<template>
  <div class="bg-slate-800/80 border border-slate-700/60 p-5 rounded-xl shadow-lg flex flex-col justify-between">
    <div class="flex justify-between items-center mb-2">
      <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">{{ title }}</span>
      <div :class="iconBgClass" class="p-2 rounded-lg">
        <slot name="icon"></slot>
      </div>
    </div>
    
    <div>
      <div class="text-3xl font-extrabold tracking-tight mt-1" :class="valueClass">
        {{ value }}
      </div>
      <p v-if="subtitle" class="text-xs text-slate-500 mt-1 font-medium">
        {{ subtitle }}
      </p>
    </div>
  </div>
</template>

<script setup>
defineProps({
  title: String,
  value: [String, Number],
  subtitle: String,
  valueClass: { type: String, default: 'text-white' },
  iconBgClass: { type: String, default: 'bg-slate-700/50 text-slate-300' }
})
</script>
