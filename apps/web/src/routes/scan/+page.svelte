<script lang="ts">
  import { onMount } from "svelte";
  import { scan, type Finding } from "$lib/api";
  import { aiConfig } from "$lib/stores/aiConfig.svelte";

  let code = $state(`// Paste your code here to scan for vulnerabilities
def get_user(user_id):
    # Potential SQL Injection
    query = "SELECT * FROM users WHERE id = " + user_id
    db.execute(query)
    
    # Potential hardcoded secret
    api_key = "abc123_redacted_for_demonstration"
    
    return db.fetchone()`);

  let isScanning = $state(false);
  let findings = $state<Finding[]>([]);
  let scanProgress = $state(0);
  let scanStatus = $state("Ready to scan");

  // Read directly from the shared store — no onMount needed
  let hasAiConfig = $derived(aiConfig.isConfigured);


  const runScan = async () => {
    isScanning = true;
    findings = [];
    scanProgress = 0;
    scanStatus = "Initializing scan...";
    
    try {
      // Step 1: Start the scan and get a scan_id
      const response = await fetch("http://localhost:8080/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code,
          language: "python",
          engines: ["sast", "secrets"],
          ai_config: hasAiConfig ? {
            provider: aiConfig.provider,
            api_key:  aiConfig.apiKey,
            model:    aiConfig.model,
            endpoint: aiConfig.endpoint || undefined,
          } : undefined
        })
      });

      if (!response.ok) throw new Error("Failed to start scan");
      const { scan_id } = await response.json();

      // Step 2: Subscribe to the SSE stream
      const eventSource = new EventSource(`http://localhost:8080/api/v1/scan/${scan_id}/events`);

      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        switch (data.type) {
          case 'progress':
            scanProgress = data.data.percentage;
            scanStatus = data.data.message;
            break;
          case 'finding':
            findings = [...findings, data.data];
            break;
          case 'complete':
            scanProgress = 100;
            scanStatus = "Scan complete!";
            isScanning = false;
            eventSource.close();
            break;
          case 'error':
            scanStatus = `Error: ${data.data}`;
            isScanning = false;
            eventSource.close();
            break;
        }
      };

      eventSource.onerror = () => {
        console.error("SSE connection failed");
        isScanning = false;
        eventSource.close();
      };
      
    } catch (error) {
      console.error("Scan failed", error);
      scanStatus = "Scan failed to initiate";
      isScanning = false;
    }
  };

  const getSeverityColor = (sev: string) => {
    switch(sev.toLowerCase()) {
      case "critical": return "bg-red-500 text-white";
      case "high": return "bg-orange-500 text-white";
      case "medium": return "bg-yellow-500 text-black";
      case "low": return "bg-blue-500 text-white";
      default: return "bg-zinc-500 text-white";
    }
  };
</script>

<div class="h-full flex flex-col gap-8 max-w-6xl mx-auto">
  <div class="flex items-center justify-between">
    <div>
      <h1 class="text-3xl font-bold font-outfit mb-2">New Security Scan</h1>
      <p class="text-zinc-500">Analyze your code for vulnerabilities, hardcoded secrets, and compliance issues.</p>
    </div>
    
    <div class="flex items-center gap-4">
      {#if hasAiConfig}
        <a 
          href="/settings/ai"
          class="flex items-center gap-2.5 px-4 py-2 glass rounded-xl border-zinc-800 hover:border-zinc-700 transition-all group"
          title="AI config loaded from Settings — click to change"
        >
          <div class="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.7)]"></div>
          <span class="text-xs font-bold text-zinc-400 group-hover:text-zinc-200 transition-colors">{provider}</span>
          <span class="text-zinc-700">/</span>
          <span class="text-xs font-mono text-zinc-500 group-hover:text-zinc-300 transition-colors max-w-[180px] truncate">{model}</span>
          <svg class="w-3 h-3 text-zinc-600 group-hover:text-zinc-400 transition-colors ml-1" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4Z"/></svg>
        </a>
      {:else}
        <a
          href="/settings/ai"
          class="flex items-center gap-2 px-4 py-2 rounded-xl border border-dashed border-zinc-700 hover:border-zinc-500 text-zinc-500 hover:text-zinc-300 transition-all text-xs font-bold"
        >
          <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>
          No AI config — click to set up
        </a>
      {/if}
      <button 
        onclick={runScan} 
        disabled={isScanning || !code.trim()}
        class="btn-primary flex items-center gap-2 {isScanning ? 'animate-pulse' : ''}"
      >
        {#if isScanning}
          <svg class="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
          Scanning...
        {:else}
          Run Scan
        {/if}
      </button>
    </div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 flex-1 min-h-0">
    <!-- Code Editor Area -->
    <div class="flex flex-col gap-4">
      <div class="flex-1 glass rounded-2xl overflow-hidden border-zinc-800 flex flex-col relative group">
        <div class="px-6 py-3 border-b border-border bg-zinc-900/50 flex items-center justify-between">
          <span class="text-xs font-bold text-zinc-500 uppercase tracking-widest">Input Code</span>
          <div class="flex gap-1.5">
            <div class="w-2.5 h-2.5 rounded-full bg-zinc-800"></div>
            <div class="w-2.5 h-2.5 rounded-full bg-zinc-800"></div>
            <div class="w-2.5 h-2.5 rounded-full bg-zinc-800"></div>
          </div>
        </div>
        <textarea
          bind:value={code}
          class="flex-1 bg-transparent p-6 font-mono text-sm resize-none outline-none text-zinc-300 leading-relaxed custom-scrollbar"
          spellcheck="false"
        ></textarea>
      </div>
    </div>

    <!-- Results Area -->
    <div class="flex flex-col gap-4 overflow-hidden">
      <div class="flex-1 glass rounded-2xl overflow-hidden border-zinc-800 flex flex-col">
        <div class="px-6 py-3 border-b border-border bg-zinc-900/50 flex items-center justify-between">
          <span class="text-xs font-bold text-zinc-500 uppercase tracking-widest">Findings ({findings.length})</span>
          {#if findings.length > 0}
             <button class="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Clear</button>
          {/if}
        </div>
        
        <div class="flex-1 overflow-y-auto p-6 space-y-4 custom-scrollbar">
          {#if isScanning || (scanProgress > 0 && scanProgress < 100)}
            <div class="p-6 mb-4 glass-card border-brand-primary/20 bg-brand-primary/5 slide-in-from-top-4 animate-in duration-500">
              <div class="flex items-center gap-6">
                <div class="relative w-16 h-16 flex-shrink-0">
                  <!-- Circular Progress -->
                  <svg class="w-full h-full -rotate-90" viewBox="0 0 100 100">
                    <circle class="text-zinc-800" cx="50" cy="50" r="45" stroke="currentColor" stroke-width="8" fill="none"></circle>
                    <circle 
                      class="text-brand-primary transition-all duration-500 ease-out" 
                      cx="50" cy="50" r="45" 
                      stroke="currentColor" 
                      stroke-width="8" 
                      fill="none"
                      stroke-dasharray="282.7"
                      stroke-dashoffset={282.7 - (282.7 * scanProgress) / 100}
                    ></circle>
                  </svg>
                  <div class="absolute inset-0 flex items-center justify-center">
                    <span class="text-xs font-black text-white">{scanProgress}%</span>
                  </div>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="flex items-center justify-between mb-2">
                    <h3 class="font-bold text-sm text-zinc-100 truncate">{scanStatus}</h3>
                    <span class="text-[10px] font-black text-brand-primary uppercase tracking-tighter animate-pulse">Live</span>
                  </div>
                  <!-- Linear Progress Bar -->
                  <div class="w-full h-1 bg-zinc-800 rounded-full overflow-hidden">
                    <div 
                      class="h-full bg-brand-primary transition-all duration-500 ease-out" 
                      style="width: {scanProgress}%"
                    ></div>
                  </div>
                </div>
              </div>
            </div>
          {/if}

          {#if findings.length === 0 && !isScanning}
            <div class="flex flex-col items-center justify-center h-full text-center space-y-2 opacity-50">
              <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" class="text-zinc-600"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
              <p class="text-sm font-medium">Ready to scan. Paste your code on the left.</p>
            </div>
          {:else}
            {#each findings as finding (finding.id || Math.random())}
              <div class="p-5 glass-card border-zinc-800 slide-in-from-right-4 animate-in duration-300">
                <div class="flex items-start justify-between gap-4 mb-4">
                  <div class="flex-1">
                    <div class="flex items-center gap-2 mb-2">
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
                      <span class="text-xs font-bold text-zinc-600">#{finding.cwe_id || 'CWE-UNKNOWN'}</span>
                    </div>
                    <h3 class="font-bold text-base leading-tight text-zinc-100">{finding.title}</h3>
                  </div>
                  <div class="text-[10px] font-mono text-zinc-500 bg-zinc-900/80 border border-zinc-800 px-2.5 py-1 rounded-md shadow-inner">
                    Line {finding.line_start}
                  </div>
                </div>
                
                {#if finding.description && finding.description !== finding.explanation}
                  <div class="mb-4 p-3 bg-zinc-900/50 rounded-xl border border-zinc-800/50 relative overflow-hidden group">
                    <div class="absolute top-0 right-0 p-2 opacity-10 group-hover:opacity-20 transition-opacity">
                      <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
                    </div>
                    <p class="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 flex items-center gap-1.5">
                      <span class="w-1.5 h-1.5 rounded-full bg-brand-primary animate-pulse"></span>
                      Official NVD Context
                    </p>
                    <p class="text-xs text-zinc-400 leading-relaxed italic">
                      "{finding.description}"
                    </p>
                  </div>
                {/if}

                <div class="space-y-4">
                  <div>
                    <p class="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-2">Technical Analysis</p>
                    <p class="text-xs text-zinc-400 leading-relaxed">
                      {finding.explanation || "No technical explanation available."}
                    </p>
                  </div>

                  <div class="bg-black/50 rounded-lg p-3 border border-zinc-800/50 font-mono text-[11px] text-zinc-500 overflow-x-auto whitespace-pre custom-scrollbar">
                    {finding.vulnerable_code}
                  </div>
                  
                  {#if finding.fixed_code}
                    <div class="flex flex-col gap-2 pt-2 border-t border-zinc-800/50">
                      <p class="text-[10px] font-bold text-emerald-500 uppercase tracking-widest flex items-center gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
                        Security Benchmark Fix
                      </p>
                      <div class="bg-emerald-500/5 rounded-lg p-3 border border-emerald-500/20 font-mono text-[11px] text-emerald-400/90 overflow-x-auto whitespace-pre custom-scrollbar">
                        {finding.fixed_code}
                      </div>
                    </div>
                  {/if}
                </div>
              </div>
            {/each}
          {/if}
        </div>
      </div>
    </div>
  </div>
</div>

<style>
  textarea::-webkit-scrollbar {
    width: 6px;
  }
  textarea::-webkit-scrollbar-track {
    background: transparent;
  }
  textarea::-webkit-scrollbar-thumb {
    background: #27272a;
    border-radius: 10px;
  }
</style>
