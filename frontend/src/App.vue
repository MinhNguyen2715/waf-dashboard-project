<template>
  <div class="min-h-screen bg-slate-900 text-slate-100 font-sans">
    <Navbar />

    <main class="max-w-7xl mx-auto px-4 py-6">
      <router-view />
    </main>
  </div>
</template>

<script setup>
import Navbar from './components/Navbar.vue'
</script>
