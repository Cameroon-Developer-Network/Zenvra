<script lang="ts">
  const stats = [
    { label: "Total Scans", value: "24", trend: "+12%", icon: "files" },
    { label: "Vulnerabilities", value: "142", trend: "+8%", icon: "alert-triangle" },
    { label: "Avg. Scan Time", value: "1.2s", trend: "-5%", icon: "zap" },
    { label: "Critical Issues", value: "12", trend: "0%", icon: "shield-alert" },
  ];

  const recentScans = [
    { id: "1", project: "Zenvra-CLI", findings: 12, date: "2 mins ago", severity: "High" },
    { id: "2", project: "Auth-Service", findings: 0, date: "1 hour ago", severity: "None" },
    { id: "3", project: "Payment-Gateway", findings: 2, date: "3 hours ago", severity: "Critical" },
    { id: "4", project: "User-Dashboard", findings: 5, date: "Yesterday", severity: "Medium" },
  ];
</script>

<div class="space-y-10">
  <!-- Hero Section -->
  <section class="relative overflow-hidden p-10 glass-card bg-gradient-to-br from-surface to-zinc-900 border-zinc-800">
    <div class="absolute top-0 right-0 w-64 h-64 bg-brand-primary/10 rounded-full blur-[100px] -mr-32 -mt-32"></div>
    <div class="relative z-10 max-w-2xl">
      <h1 class="text-4xl font-bold font-outfit tracking-tight mb-4 leading-tight">
        Ship fast. <span class="text-gradient">Ship safe.</span>
      </h1>
      <p class="text-lg text-zinc-400 mb-8 max-w-lg">
        AI-powered code vulnerability scanner designed for the vibe coding era. Scan, detect, and fix security issues in seconds.
      </p>
      <div class="flex gap-4">
        <a href="/scan" class="btn-primary flex items-center gap-2 shadow-lg shadow-brand-primary/20">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/></svg>
          New Scan
        </a>
        <button class="btn-outline">Watch Demo</button>
      </div>
    </div>
  </section>

  <!-- Stats Grid -->
  <section class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
    {#each stats as stat}
      <div class="glass-card p-6 flex flex-col justify-between hover:translate-y-[-4px]">
        <div class="flex items-center justify-between mb-4">
          <span class="text-sm font-semibold text-zinc-500 uppercase tracking-wider">{stat.label}</span>
          <span class="text-[10px] font-bold px-2 py-0.5 rounded-full {stat.trend.startsWith('+') ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}">
            {stat.trend}
          </span>
        </div>
        <div class="text-3xl font-bold font-outfit">{stat.value}</div>
      </div>
    {/each}
  </section>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
    <!-- Recent Scans -->
    <section class="lg:col-span-2 space-y-6">
      <div class="flex items-center justify-between">
        <h2 class="text-xl font-bold font-outfit">Recent Activity</h2>
        <button class="text-sm font-medium text-brand-primary hover:underline">View all reports</button>
      </div>
      <div class="glass-card overflow-hidden border-zinc-800 animate-in fade-in slide-in-from-bottom-4 duration-700">
        <table class="w-full text-left">
          <thead class="bg-zinc-800/20 text-xs text-zinc-500 font-bold uppercase tracking-widest border-b border-border">
            <tr>
              <th class="px-6 py-4">Project / File</th>
              <th class="px-6 py-4 text-center">Findings</th>
              <th class="px-6 py-4">Severity</th>
              <th class="px-6 py-4">Date</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-border">
            {#each recentScans as scan}
              <tr class="hover:bg-white/5 transition-colors cursor-pointer group">
                <td class="px-6 py-4 font-medium">{scan.project}</td>
                <td class="px-6 py-4 text-center text-zinc-400">{scan.findings}</td>
                <td class="px-6 py-4">
                  <span class="text-xs font-bold px-2 py-0.5 rounded-full 
                    {scan.severity === 'Critical' ? 'bg-red-500/20 text-red-500' : 
                     scan.severity === 'High' ? 'bg-orange-500/20 text-orange-500' : 
                     scan.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-500' : 
                     'bg-zinc-800 text-zinc-400'}">
                    {scan.severity}
                  </span>
                </td>
                <td class="px-6 py-4 text-zinc-500 text-sm">{scan.date}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <!-- AI Providers -->
    <section class="space-y-6">
      <h2 class="text-xl font-bold font-outfit">Active Providers</h2>
      <div class="space-y-4">
        {#each ['Anthropic', 'OpenAI', 'Google', 'Custom'] as provider}
          <div class="glass-card p-4 flex items-center justify-between group {provider === 'Anthropic' ? 'border-brand-primary/30' : ''}">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-xl glass flex items-center justify-center {provider === 'Anthropic' ? 'bg-brand-primary/5 text-brand-primary' : 'text-zinc-500 group-hover:text-zinc-200'}">
                {#if provider === 'Anthropic'}A{:else if provider === 'OpenAI'}O{:else if provider === 'Google'}G{:else}C{/if}
              </div>
              <div class="text-sm font-semibold">{provider}</div>
            </div>
            {#if provider === 'Anthropic'}
              <div class="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
            {:else if provider === 'Custom'}
               <button class="text-xs text-brand-primary font-bold hover:underline">Configure</button>
            {/if}
          </div>
        {/each}
      </div>
    </section>
  </div>
</div>
