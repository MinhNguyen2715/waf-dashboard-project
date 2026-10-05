<template>
  <header class="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="p-2 bg-blue-600/20 rounded-lg text-blue-400">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <h1 class="text-lg font-bold tracking-wide text-white">WAF SECURITY DASHBOARD</h1>
          <!-- <p class="text-xs text-slate-400">ModSecurity + OWASP CRS v4 Protection</p> -->
        </div>
      </div>

      <nav class="flex items-center space-x-4">
        <router-link to="/" class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors" active-class="bg-blue-600/20 text-blue-400 border border-blue-500/30">
          Dashboard
        </router-link>
        <router-link to="/logs" class="px-3 py-1.5 rounded-lg text-sm font-medium text-slate-400 hover:text-slate-200 transition-colors" active-class="bg-blue-600/20 text-blue-400 border border-blue-500/30">
          Detailed Logs
        </router-link>
        
        <!-- Live Status Indicator -->
        <div class="flex items-center space-x-2 pl-4 border-l border-slate-800">
          <span class="relative flex h-3 w-3">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span class="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
          </span>
          <span class="text-xs font-semibold text-emerald-400 uppercase tracking-wider">SYSTEM ACTIVE</span>
        </div>
      </nav>
    </div>
  </header>
</template>
