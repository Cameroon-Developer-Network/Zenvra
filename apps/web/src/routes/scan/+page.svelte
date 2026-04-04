<script lang="ts">

  let code = $state(`// Paste your code here to scan for vulnerabilities
def insecure_database_query(user_id):
    # Potential SQL Injection
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    
    # Potential hardcoded secret
    stripe_key = "SK_LIVE_REDACTED_FOR_TESTING"
    
    return cursor.fetchone()`);

  interface Finding {
    id: string;
    severity: string;
    cwe_id?: string;
    title: string;
    line_start: number;
    description?: string;
    explanation?: string;
    vulnerable_code: string;
    fixed_code?: string;
  }

  let isScanning = $state(false);
  let findings = $state<Finding[]>([]);
  let provider = $state("anthropic");
  let model = $state("claude-sonnet-4-20250514");

  const runScan = async () => {
    isScanning = true;
    findings = [];
    
    try {
      const response = await fetch("http://localhost:8080/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code,
          language: "python",
          engines: ["sast", "secrets"],
          ai_config: {
            provider,
            api_key: "dummy-key", // In production this would come from secure storage or user session
            model,
          }
        })
      });
      
      if (response.ok) {
        findings = await response.json();
      }
    } catch (error) {
      console.error("Scan failed", error);
    } finally {
      isScanning = false;
    }
  };

  const getSeverityColor = (sev: string) => {
    switch(sev) {
      case "Critical": return "bg-red-500 text-white";
      case "High": return "bg-orange-500 text-white";
      case "Medium": return "bg-yellow-500 text-black";
      case "Low": return "bg-blue-500 text-white";
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
      <div class="flex items-center glass p-1 rounded-xl">
        <select bind:value={provider} class="bg-transparent text-sm font-semibold px-3 py-1 outline-none">
          <option value="anthropic">Anthropic</option>
          <option value="openai">OpenAI</option>
          <option value="google">Google</option>
          <option value="custom">Custom</option>
        </select>
        <div class="w-px h-4 bg-border mx-1"></div>
        <input 
          bind:value={model} 
          class="bg-transparent text-sm text-zinc-400 px-3 py-1 outline-none min-w-[200px]" 
          placeholder="Model name..."
        />
      </div>
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
          {#if isScanning}
            <div class="flex flex-col items-center justify-center h-full text-center space-y-4">
              <div class="w-12 h-12 rounded-2xl bg-brand-primary/10 flex items-center justify-center text-brand-primary animate-bounce">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/></svg>
              </div>
              <div>
                <p class="font-bold text-zinc-200">Analyzing Code...</p>
                <p class="text-xs text-zinc-500 mt-1">Running SAST and Secret engines</p>
              </div>
            </div>
          {:else if findings.length === 0}
            <div class="flex flex-col items-center justify-center h-full text-center space-y-2 opacity-50">
              <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" class="text-zinc-600"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
              <p class="text-sm font-medium">Ready to scan. Paste your code on the left.</p>
            </div>
          {:else}
            {#each findings as finding (finding.id || Math.random())}
              <div class="p-4 glass-card border-zinc-800 slide-in-from-right-4 animate-in duration-300">
                <div class="flex items-start justify-between gap-4 mb-3">
                  <div class="flex-1">
                    <div class="flex items-center gap-2 mb-1">
                      <span class="text-[10px] font-black px-1.5 py-0.5 rounded {getSeverityColor(finding.severity)} uppercase tracking-tighter">
                        {finding.severity}
                      </span>
                      <span class="text-xs font-bold text-zinc-500">#{finding.cwe_id || 'UNKNOWN'}</span>
                    </div>
                    <h3 class="font-bold text-sm leading-tight text-zinc-200">{finding.title}</h3>
                  </div>
                  <div class="text-[10px] font-medium text-zinc-500 bg-zinc-800/50 px-2 py-1 rounded">
                    Line {finding.line_start}
                  </div>
                </div>
                
                <p class="text-xs text-zinc-400 leading-relaxed mb-4">
                  {finding.description || finding.explanation || "No description provided."}
                </p>

                <div class="bg-black/50 rounded-lg p-3 border border-zinc-800/50 font-mono text-[11px] text-zinc-500 overflow-x-auto whitespace-pre">
                  {finding.vulnerable_code}
                </div>
                
                {#if finding.fixed_code}
                  <div class="mt-4 flex flex-col gap-2">
                    <p class="text-[10px] font-bold text-emerald-500 uppercase tracking-widest">Suggested Fix</p>
                    <div class="bg-emerald-500/5 rounded-lg p-3 border border-emerald-500/20 font-mono text-[11px] text-emerald-400 overflow-x-auto whitespace-pre">
                      {finding.fixed_code}
                    </div>
                  </div>
                {/if}
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
