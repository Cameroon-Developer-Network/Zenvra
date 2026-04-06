<script lang="ts">
  import { onMount } from "svelte";
  import { getHistory, type ScanHistory } from "$lib/api";

  let history = $state<ScanHistory[]>([]);
  let isLoading = $state(true);
  let error = $state<string | null>(null);

  const fetchHistory = async () => {
    isLoading = true;
    error = null;
    try {
      history = await getHistory();
    } catch (err: unknown) {
      console.error("Failed to load history", err);
      const errorMsg = err instanceof Error ? err.message : String(err);
      error = errorMsg || "An unexpected error occurred while loading your history.";
    } finally {
      isLoading = false;
    }
  };

  onMount(() => {
    fetchHistory();
  });

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getSeverityColor = (sev: string) => {
    switch(sev.toLowerCase()) {
      case "critical": return "bg-red-500";
      case "high": return "bg-orange-500";
      case "medium": return "bg-yellow-500";
      case "low": return "bg-blue-500";
      default: return "bg-zinc-500";
    }
  };
</script>

<div class="max-w-6xl mx-auto space-y-8">
  <div class="flex items-end justify-between">
    <div>
      <h1 class="text-3xl font-bold font-outfit mb-2">Scan History</h1>
      <p class="text-zinc-500">Review past security assessments and tracking vulnerability trends.</p>
    </div>
    <div class="flex gap-2">
      <button 
        onclick={fetchHistory}
        disabled={isLoading}
        class="glass px-4 py-2 rounded-xl border-zinc-800 hover:bg-white/5 transition-all flex items-center gap-2 group"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class={isLoading ? "animate-spin" : "group-hover:rotate-180 transition-transform duration-500"}><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>
        <span class="text-xs font-bold">Refresh</span>
      </button>
      <div class="glass px-4 py-2 rounded-xl border-zinc-800 flex items-center gap-2">
         <span class="text-xs font-bold text-zinc-500 uppercase tracking-widest">Total:</span>
         <span class="text-sm font-bold tracking-widest">{history.length}</span>
      </div>
    </div>
  </div>

  {#if isLoading}
    <div class="grid grid-cols-1 gap-4">
      {#each Array(5) as __, i (i)}
        <div class="h-24 glass rounded-2xl animate-pulse border-zinc-800/50"></div>
      {/each}
    </div>
  {:else if error}
    <div class="h-[300px] glass rounded-3xl border-red-500/20 bg-red-500/5 flex flex-col items-center justify-center text-center p-12">
      <div class="w-12 h-12 rounded-xl bg-red-500/10 flex items-center justify-center text-red-500 mb-4">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      </div>
      <h3 class="font-bold text-red-200">Connection Failed</h3>
      <p class="text-sm text-red-400/70 max-w-sm mt-2">{error}</p>
      <button onclick={() => window.location.reload()} class="mt-6 px-6 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-200 text-xs font-bold rounded-xl transition-all">Retry Connection</button>
    </div>
  {:else if history.length === 0}
    <div class="h-[400px] glass rounded-3xl border-zinc-800 border-dashed flex flex-col items-center justify-center text-center p-12">
      <div class="w-16 h-16 rounded-2xl bg-zinc-900 flex items-center justify-center text-zinc-700 mb-4">
        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="10"/></svg>
      </div>
      <h3 class="text-lg font-bold text-zinc-300">No scans found</h3>
      <p class="text-zinc-500 max-w-xs mt-2">You haven't performed any code scans yet. Start your first scan to see your history here.</p>
      <a href="/scan" class="mt-6 btn-primary">Start New Scan</a>
    </div>
  {:else}
    <div class="grid grid-cols-1 gap-4">
      {#each history as scan (scan.id)}
        <div class="glass-card p-6 border-zinc-800 hover:border-zinc-700 transition-all group relative overflow-hidden">
          <div class="flex items-center justify-between relative z-10">
            <div class="flex items-center gap-6">
              <div class="w-12 h-12 rounded-xl bg-zinc-900 border border-zinc-800 flex items-center justify-center text-zinc-400 group-hover:text-brand-primary transition-colors">
                {#if scan.language.toLowerCase() === 'python'}
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
                {:else}
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>
                {/if}
              </div>
              
              <div>
                <div class="flex items-center gap-3 mb-1">
                  <h3 class="font-bold text-zinc-200">{scan.target_name || 'Unnamed Scan'}</h3>
                  <span class="text-[10px] font-bold bg-zinc-800 text-zinc-500 px-2 py-0.5 rounded uppercase tracking-wider">{scan.language}</span>
                </div>
                <p class="text-xs text-zinc-500 font-medium">{formatDate(scan.created_at)}</p>
              </div>
            </div>

            <div class="flex items-center gap-8">
              <div class="flex gap-1.5 item">
                {#each Object.entries(scan.severity_counts) as [severity, count] (severity)}
                  {#if count > 0}
                    <div class="flex flex-col items-center">
                      <div class="w-2 h-2 rounded-full {getSeverityColor(severity)} mb-1 shadow-[0_0_8px_rgba(255,255,255,0.2)]"></div>
                      <span class="text-[10px] font-bold text-zinc-500">{count}</span>
                    </div>
                  {/if}
                {/each}
              </div>

              <div class="text-right">
                <p class="text-lg font-bold text-zinc-100">{scan.findings_count}</p>
                <p class="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Findings</p>
              </div>

              <button class="w-10 h-10 rounded-xl glass border-zinc-800 flex items-center justify-center text-zinc-500 hover:text-white hover:bg-white/5 transition-all">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
              </button>
            </div>
          </div>
          
          <!-- Background accent -->
          <div class="absolute top-0 right-0 w-32 h-32 bg-brand-primary/5 blur-3xl rounded-full translate-x-16 -translate-y-16 opacity-0 group-hover:opacity-100 transition-opacity duration-700"></div>
        </div>
      {/each}
    </div>
  {/if}
</div>
