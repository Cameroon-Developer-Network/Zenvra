<script lang="ts">
  import { triggerSync } from "$lib/api";

  let isSyncing = $state(false);
  let lastSyncStatus = $state<string | null>(null);
  let statusMessage = $state("");

  const handleSync = async () => {
    isSyncing = true;
    lastSyncStatus = null;
    statusMessage = "Starting data ingestion from NVD & OSV...";

    try {
      const res = await triggerSync();
      lastSyncStatus = "success";
      statusMessage = res.message;
    } catch (err: unknown) {
      lastSyncStatus = "error";
      const errorMsg = err instanceof Error ? err.message : String(err);
      statusMessage = errorMsg || "Failed to synchronize vulnerability databases.";
    } finally {
      isSyncing = false;
    }
  };
</script>

<div class="max-w-4xl mx-auto space-y-8">
  <div class="flex items-end justify-between">
    <div>
      <h1 class="text-3xl font-bold font-outfit mb-2">CVE Settings</h1>
      <p class="text-zinc-500">Manage vulnerability data feeds and local database synchronization.</p>
    </div>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <!-- NVD Status Card -->
    <div class="glass p-8 rounded-3xl border-zinc-800 relative overflow-hidden group">
      <div class="flex items-start justify-between mb-6">
        <div class="w-12 h-12 rounded-2xl bg-brand-primary/10 flex items-center justify-center text-brand-primary">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
        </div>
        <span class="text-[10px] font-bold bg-emerald-500/10 text-emerald-500 px-2 py-1 rounded tracking-widest uppercase">Connected</span>
      </div>
      <h3 class="text-xl font-bold mb-2">NVD Data Feed</h3>
      <p class="text-sm text-zinc-500 leading-relaxed max-w-[240px]">Synchronizing with the National Vulnerability Database via API v2.</p>
      
      <div class="mt-8 space-y-3">
        <div class="flex justify-between text-xs text-zinc-500">
          <span>Synced CVEs</span>
          <span class="text-zinc-300 font-bold tracking-widest">100+</span>
        </div>
        <div class="w-full bg-zinc-900 h-1.5 rounded-full overflow-hidden">
          <div class="bg-brand-primary w-2/5 h-full rounded-full"></div>
        </div>
      </div>
    </div>

    <!-- OSV Status Card -->
    <div class="glass p-8 rounded-3xl border-zinc-800 relative overflow-hidden group">
      <div class="flex items-start justify-between mb-6">
        <div class="w-12 h-12 rounded-2xl bg-brand-primary/10 flex items-center justify-center text-brand-primary">
           <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
        </div>
        <span class="text-[10px] font-bold bg-emerald-500/10 text-emerald-500 px-2 py-1 rounded tracking-widest uppercase">Connected</span>
      </div>
      <h3 class="text-xl font-bold mb-2">OSV Ecosystems</h3>
      <p class="text-sm text-zinc-500 leading-relaxed max-w-[240px]">Unified open-source vulnerability feed for npm, PyPI, Go, and crates.io.</p>
      
      <div class="mt-8 flex flex-wrap gap-2">
        <span class="px-2 py-1 rounded-md bg-zinc-900 border border-zinc-800 text-[10px] font-mono text-zinc-400">npm</span>
        <span class="px-2 py-1 rounded-md bg-zinc-900 border border-zinc-800 text-[10px] font-mono text-zinc-400">PyPI</span>
        <span class="px-2 py-1 rounded-md bg-zinc-900 border border-zinc-800 text-[10px] font-mono text-zinc-400">Go</span>
        <span class="px-2 py-1 rounded-md bg-zinc-900 border border-zinc-800 text-[10px] font-mono text-zinc-400">crates.io</span>
      </div>
    </div>
  </div>

  <!-- Manual Sync Panel -->
  <div class="glass rounded-3xl border-zinc-800 p-8 flex flex-col items-center text-center space-y-6">
    <div class="max-w-md">
      <h3 class="text-xl font-bold mb-2">Synchronize Database</h3>
      <p class="text-sm text-zinc-500 font-medium">Manually trigger a full update from indexed databases. This ensures your scanner has the absolute latest security advisories.</p>
    </div>

    <button 
      onclick={handleSync}
      disabled={isSyncing}
      class="btn-primary flex items-center gap-2 group min-w-[180px] justify-center"
    >
      {#if isSyncing}
        <svg class="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
        Synchronizing...
      {:else}
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="group-hover:rotate-180 transition-transform duration-500"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>
        Sync Now
      {/if}
    </button>

    {#if statusMessage}
      <div class="slide-in-from-top-2 animate-in duration-300 p-3 rounded-xl border max-w-lg w-full flex items-center gap-3 {lastSyncStatus === 'success' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500' : lastSyncStatus === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-500' : 'bg-zinc-800 border-zinc-700 text-zinc-400'}">
        <div class="flex-1 text-xs font-medium">{statusMessage}</div>
      </div>
    {/if}
  </div>
</div>
