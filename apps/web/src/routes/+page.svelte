<script lang="ts">
  import { onMount } from "svelte";
  import { getHistory, type ScanHistory } from "$lib/api";
  import { aiConfig } from "$lib/stores/aiConfig.svelte";

  let history = $state<ScanHistory[]>([]);
  let isLoading = $state(true);

  const totalScans = $derived(history.length);
  const totalFindings = $derived(history.reduce((sum, s) => sum + s.findings_count, 0));
  const criticalCount = $derived(history.reduce((sum, s) => sum + (s.severity_counts['critical'] ?? 0), 0));
  const recentScans = $derived(history.slice(0, 5));

  const stats = $derived([
    { label: "Total Scans",    value: String(totalScans),   icon: "files" },
    { label: "Vulnerabilities", value: String(totalFindings), icon: "alert-triangle" },
    { label: "AI Provider",    value: aiConfig.isConfigured ? aiConfig.provider.charAt(0).toUpperCase() + aiConfig.provider.slice(1) : "None", icon: "sparkles" },
    { label: "Critical Issues", value: String(criticalCount), icon: "shield-alert" },
  ]);

  const getSeverityColor = (sev: string) => {
    switch(sev.toLowerCase()) {
      case "critical": return "bg-red-500/20 text-red-500";
      case "high":     return "bg-orange-500/20 text-orange-500";
      case "medium":   return "bg-yellow-500/20 text-yellow-500";
      case "low":      return "bg-blue-500/20 text-blue-400";
      default:         return "bg-zinc-800 text-zinc-400";
    }
  };

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr);
    const diff = Date.now() - d.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1)  return "just now";
    if (mins < 60) return `${mins} min ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24)  return `${hrs} hour${hrs > 1 ? "s" : ""} ago`;
    const days = Math.floor(hrs / 24);
    if (days === 1) return "Yesterday";
    return `${days} days ago`;
  };

  const topSeverity = (scan: ScanHistory): string => {
    for (const sev of ["critical", "high", "medium", "low"]) {
      if ((scan.severity_counts[sev] ?? 0) > 0) return sev.charAt(0).toUpperCase() + sev.slice(1);
    }
    return scan.findings_count === 0 ? "None" : "Info";
  };

  onMount(async () => {
    try {
      history = await getHistory();
    } catch {
      // History API unavailable — keep empty array (no crash)
    } finally {
      isLoading = false;
    }
  });
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
        <a href="/history" class="btn-outline">View History</a>
      </div>
    </div>
  </section>

  <!-- Stats Grid -->
  <section class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
    {#each stats as stat (stat.label)}
      <div class="glass-card p-6 flex flex-col justify-between hover:translate-y-[-4px]">
        <div class="flex items-center justify-between mb-4">
          <span class="text-sm font-semibold text-zinc-500 uppercase tracking-wider">{stat.label}</span>
        </div>
        {#if isLoading}
          <div class="h-9 w-16 bg-zinc-800 rounded animate-pulse"></div>
        {:else}
          <div class="text-3xl font-bold font-outfit">{stat.value}</div>
        {/if}
      </div>
    {/each}
  </section>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
    <!-- Recent Scans -->
    <section class="lg:col-span-2 space-y-6">
      <div class="flex items-center justify-between">
        <h2 class="text-xl font-bold font-outfit">Recent Activity</h2>
        <a href="/history" class="text-sm font-medium text-brand-primary hover:underline">View all reports</a>
      </div>
      <div class="glass-card overflow-hidden border-zinc-800 animate-in fade-in slide-in-from-bottom-4 duration-700">
        {#if isLoading}
          <div class="p-6 space-y-3">
            {#each Array.from({ length: 4 }, (_, i) => i) as i (i)}
              <div class="h-12 bg-zinc-800/50 rounded animate-pulse"></div>
            {/each}
          </div>
        {:else if recentScans.length === 0}
          <div class="p-12 text-center">
            <p class="text-zinc-500 text-sm">No scans yet. <a href="/scan" class="text-brand-primary hover:underline">Run your first scan →</a></p>
          </div>
        {:else}
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
              {#each recentScans as scan (scan.id)}
                <tr class="hover:bg-white/5 transition-colors cursor-pointer group" onclick={() => window.location.href = `/history/${scan.id}`}>
                  <td class="px-6 py-4 font-medium">{scan.target_name || 'Unnamed Scan'}<span class="ml-2 text-[10px] font-bold bg-zinc-800 text-zinc-500 px-1.5 py-0.5 rounded uppercase">{scan.language}</span></td>
                  <td class="px-6 py-4 text-center text-zinc-400">{scan.findings_count}</td>
                  <td class="px-6 py-4">
                    <span class="text-xs font-bold px-2 py-0.5 rounded-full {getSeverityColor(topSeverity(scan))}">
                      {topSeverity(scan)}
                    </span>
                  </td>
                  <td class="px-6 py-4 text-zinc-500 text-sm">{formatDate(scan.created_at)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </section>

    <!-- AI Providers -->
    <section class="space-y-6">
      <h2 class="text-xl font-bold font-outfit">Active Providers</h2>
      <div class="space-y-4">
        {#each ['Anthropic', 'OpenAI', 'Google', 'Custom'] as provider (provider)}
          {@const isActive = aiConfig.isConfigured && aiConfig.provider.toLowerCase() === provider.toLowerCase()}
          <div class="glass-card p-4 flex items-center justify-between group {isActive ? 'border-brand-primary/30' : ''}">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-xl glass flex items-center justify-center {isActive ? 'bg-brand-primary/5 text-brand-primary' : 'text-zinc-500 group-hover:text-zinc-200'}">
                {#if provider === 'Anthropic'}A{:else if provider === 'OpenAI'}O{:else if provider === 'Google'}G{:else}C{/if}
              </div>
              <div class="text-sm font-semibold">{provider}</div>
            </div>
            {#if isActive}
              <div class="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
            {:else}
               <a href="/settings/ai" class="text-xs text-brand-primary font-bold hover:underline">Configure</a>
            {/if}
          </div>
        {/each}
      </div>
    </section>
  </div>
</div>
