<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import { getScanResults, type Finding } from "$lib/api";

  const scanId = page.params.id;

  let findings = $state<Finding[]>([]);
  let isLoading = $state(true);
  let error = $state<string | null>(null);

  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return "bg-red-500 text-white";
      case "high":     return "bg-orange-500 text-white";
      case "medium":   return "bg-yellow-500 text-black";
      case "low":      return "bg-blue-500 text-white";
      default:         return "bg-zinc-500 text-white";
    }
  };

  const getSeverityBorderColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return "border-red-500/30";
      case "high":     return "border-orange-500/30";
      case "medium":   return "border-yellow-500/30";
      case "low":      return "border-blue-500/30";
      default:         return "border-zinc-700";
    }
  };

  onMount(async () => {
    try {
      if (scanId) {
        findings = await getScanResults(scanId);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      error = msg || "Failed to load scan results.";
    } finally {
      isLoading = false;
    }
  });
</script>

<div class="max-w-4xl mx-auto space-y-8 animate-in fade-in duration-500">
  <div class="flex items-center gap-4">
    <a
      href="/history"
      class="flex items-center gap-2 text-zinc-500 hover:text-zinc-200 transition-colors text-sm font-medium"
    >
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg>
      Back to History
    </a>
  </div>

  <div>
    <h1 class="text-3xl font-bold font-outfit mb-2">Scan Report</h1>
    <p class="text-zinc-500 font-mono text-xs">{scanId}</p>
  </div>

  {#if isLoading}
    <div class="space-y-4">
      {#each Array.from({ length: 4 }, (_, i) => i) as i (i)}
        <div class="h-32 glass rounded-2xl animate-pulse border-zinc-800/50"></div>
      {/each}
    </div>

  {:else if error}
    <div class="h-[300px] glass rounded-3xl border-red-500/20 bg-red-500/5 flex flex-col items-center justify-center text-center p-12">
      <div class="w-12 h-12 rounded-xl bg-red-500/10 flex items-center justify-center text-red-500 mb-4">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      </div>
      <h3 class="font-bold text-red-200">Failed to load results</h3>
      <p class="text-sm text-red-400/70 max-w-sm mt-2">{error}</p>
      <button onclick={() => window.location.reload()} class="mt-6 px-6 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-200 text-xs font-bold rounded-xl transition-all">Retry</button>
    </div>

  {:else if findings.length === 0}
    <div class="h-[400px] glass rounded-3xl border-zinc-800 border-dashed flex flex-col items-center justify-center text-center p-12">
      <div class="w-16 h-16 rounded-2xl bg-zinc-900 flex items-center justify-center text-zinc-600 mb-4">
        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>
      </div>
      <h3 class="text-lg font-bold text-zinc-300">No findings</h3>
      <p class="text-zinc-500 max-w-xs mt-2">This scan completed with zero vulnerabilities detected.</p>
    </div>

  {:else}
    <!-- Summary bar -->
    <div class="flex items-center gap-4 p-4 glass rounded-2xl border-zinc-800">
      <div class="flex-1 text-sm font-medium text-zinc-400">
        <span class="text-zinc-100 font-bold">{findings.length}</span> finding{findings.length === 1 ? '' : 's'} detected
      </div>
      <div class="flex gap-2">
        {#each ['critical', 'high', 'medium', 'low'] as sev (sev)}
          {@const count = findings.filter(f => f.severity === sev).length}
          {#if count > 0}
            <span class="text-[10px] font-black px-2 py-1 rounded {getSeverityColor(sev)} uppercase tracking-tighter">
              {count} {sev}
            </span>
          {/if}
        {/each}
      </div>
    </div>

    <div class="space-y-4">
      {#each findings as finding (finding.id)}
        <div class="p-5 glass-card {getSeverityBorderColor(finding.severity)} slide-in-from-bottom-4 animate-in duration-300">
          <div class="flex items-start justify-between gap-4 mb-4">
            <div class="flex-1">
              <div class="flex items-center gap-2 mb-2 flex-wrap">
                <span class="text-[10px] font-black px-1.5 py-0.5 rounded {getSeverityColor(finding.severity)} uppercase tracking-tighter">
                  {finding.severity}
                </span>
                {#if finding.cve_id}
                  <a
                    href="https://nvd.nist.gov/vuln/detail/{finding.cve_id}"
                    target="_blank"
                    class="text-[10px] font-bold text-brand-primary bg-brand-primary/10 px-1.5 py-0.5 rounded hover:bg-brand-primary/20 transition-colors uppercase"
                  >
                    {finding.cve_id}
                  </a>
                {/if}
                {#if finding.cwe_id}
                  <span class="text-xs font-bold text-zinc-600">#{finding.cwe_id}</span>
                {/if}
                <span class="text-[10px] font-bold bg-zinc-800 text-zinc-500 px-1.5 py-0.5 rounded uppercase tracking-tighter">
                  {finding.engine}
                </span>
              </div>
              <h3 class="font-bold text-base leading-tight text-zinc-100">{finding.title}</h3>
            </div>
            <div class="flex flex-col items-end gap-1 flex-shrink-0">
              <div class="text-[10px] font-mono text-zinc-500 bg-zinc-900/80 border border-zinc-800 px-2.5 py-1 rounded-md">
                Line {finding.line_start}
              </div>
              {#if finding.file_path}
                <div class="text-[10px] font-mono text-zinc-600 truncate max-w-[160px]" title={finding.file_path}>
                  {finding.file_path}
                </div>
              {/if}
            </div>
          </div>

          {#if finding.description}
            <div class="mb-4 p-3 bg-zinc-900/50 rounded-xl border border-zinc-800/50">
              <p class="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 flex items-center gap-1.5">
                <span class="w-1.5 h-1.5 rounded-full bg-brand-primary"></span>
                Context
              </p>
              <p class="text-xs text-zinc-400 leading-relaxed">{finding.description}</p>
            </div>
          {/if}

          <div class="space-y-3">
            <div>
              <p class="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-2">Vulnerable Code</p>
              <div class="bg-black/50 rounded-lg p-3 border border-zinc-800/50 font-mono text-[11px] text-zinc-500 overflow-x-auto whitespace-pre custom-scrollbar">
                {finding.vulnerable_code}
              </div>
            </div>

            {#if finding.fixed_code}
              <div>
                <p class="text-[10px] font-bold text-emerald-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                  <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
                  Security Fix
                </p>
                <div class="bg-emerald-500/5 rounded-lg p-3 border border-emerald-500/20 font-mono text-[11px] text-emerald-400/90 overflow-x-auto whitespace-pre custom-scrollbar">
                  {finding.fixed_code}
                </div>
              </div>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>
