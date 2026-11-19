<template>
  <div class="bg-slate-800/80 border border-slate-700/60 p-5 rounded-xl shadow-lg h-full flex flex-col">
    <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4">
      Attack Types Distribution
    </h3>
    <div class="flex-1 relative flex items-center justify-center min-h-[220px]">
      <Doughnut v-if="chartData.labels.length > 0" :data="chartData" :options="chartOptions" />
      <p v-else class="text-sm text-slate-500">No attack data logged yet</p>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js'
import { Doughnut } from 'vue-chartjs'

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps({
  distribution: {
    type: Object,
    default: () => ({})
  }
})

const stringToColor = (str, index = 0, total = 1) => {
  if (!str) return 'hsl(0, 75%, 50%)'
  
  // Bắt đầu từ 0° (màu Đỏ) và chia đều 360° theo số lượng nhãn hiện có
  const hue = Math.floor((index * (360 / total)) % 360)
  return `hsl(${hue}, 80%, 55%)`
}

const chartData = computed(() => {
  const labels = Object.keys(props.distribution)
  const data = Object.values(props.distribution)
  const total = labels.length || 1

  const backgroundColor = labels.map((label, index) => stringToColor(label, index, total))

  return {
    labels,
    datasets: [
      {
        backgroundColor,
        borderColor: '#1e293b',
        borderWidth: 2,
        data
      }
    ]
  }
})

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'bottom',
      labels: { color: '#94a3b8', font: { size: 11 } }
    }
  }
}
</script>
