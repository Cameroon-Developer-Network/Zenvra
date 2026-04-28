<script lang="ts">
  import { fetchAiModels } from "$lib/api";
  import { aiConfig } from "$lib/stores/aiConfig.svelte";

  // Local editing state — pre-populated from the shared store
  let provider       = $state(aiConfig.provider);
  let selectedModel  = $state(aiConfig.model);
  let apiKey         = $state(aiConfig.apiKey);
  let endpoint       = $state(aiConfig.endpoint);

  let availableModels = $state<string[]>(aiConfig.model ? [aiConfig.model] : []);
  let isLoadingModels = $state(false);
  let error           = $state<string | null>(null);
  let saveSuccess     = $state(false);
  let successTimer: ReturnType<typeof setTimeout>;

  // Reflects what's currently committed in the store
  let savedConfig = $derived(
    aiConfig.isConfigured ? { provider: aiConfig.provider, model: aiConfig.model } : null
  );

  const providers = [
    { id: "anthropic", name: "Anthropic",      color: "bg-[#7c3aed]", icon: "A" },
    { id: "openai",    name: "OpenAI",          color: "bg-[#10a37f]", icon: "O" },
    { id: "google",    name: "Google Gemini",   color: "bg-[#4285f4]", icon: "G" },
    { id: "custom",    name: "Custom Provider", color: "bg-zinc-600",  icon: "C" }
  ];

  const fetchModels = async () => {
    if (!apiKey) { error = "Please provide an API key first."; return; }
    isLoadingModels = true;
    error = null;
    availableModels = [];
    try {
      availableModels = await fetchAiModels(provider, apiKey, endpoint);
      if (availableModels.length > 0) selectedModel = availableModels[0];
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      error = errorMsg || "Failed to fetch models. Check your API key and connection.";
    } finally {
      isLoadingModels = false;
    }
  };

  const handleSave = () => {
    if (!selectedModel.trim()) { error = "Model name is required."; return; }
    if (!apiKey.trim())        { error = "API key is required.";    return; }
    error = null;

    // Persist via the store — writes localStorage atomically
    aiConfig.save(provider, selectedModel.trim(), apiKey.trim(), endpoint.trim());

    saveSuccess = true;
    clearTimeout(successTimer);
    successTimer = setTimeout(() => { saveSuccess = false; }, 3500);
  };
</script>

<div class="max-w-4xl mx-auto space-y-8 animate-in fade-in duration-500">
  <div class="flex items-end justify-between">
    <div>
      <h1 class="text-3xl font-bold font-outfit mb-2 tracking-tight">AI Settings</h1>
      <p class="text-zinc-500 text-sm">Configure the intelligence engine for vulnerability explanations and fix suggestions.</p>
    </div>
    <!-- Active config badge -->
    {#if savedConfig}
      <div class="flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-bold">
        <div class="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.6)]"></div>
        Active: {savedConfig.model}
      </div>
    {/if}
  </div>

  <!-- Success Banner -->
  {#if saveSuccess}
    <div class="flex items-center gap-3 p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm font-medium animate-in slide-in-from-top-2 duration-300">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
      Configuration saved. Zenvra will now use <strong class="text-emerald-300 ml-1">{selectedModel}</strong>.
    </div>
  {/if}

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
    <div class="lg:col-span-2 space-y-6">
      <div class="glass p-8 rounded-3xl border-zinc-800 space-y-8 relative overflow-hidden">
        <!-- Provider Selection -->
        <div class="space-y-4">
          <label class="block">
            <span class="text-[10px] font-black text-zinc-500 uppercase tracking-[0.2em] mb-4 block">1. Choose Intelligence Provider</span>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {#each providers as p (p.id)}
                <button
                  onclick={() => { provider = p.id; availableModels = []; selectedModel = ""; error = null; }}
                  class="p-4 rounded-2xl border transition-all flex flex-col gap-3 items-center text-center {provider === p.id ? 'border-brand-primary bg-brand-primary/5 ring-1 ring-brand-primary/20' : 'border-zinc-800 bg-zinc-900/50 hover:bg-zinc-800 hover:border-zinc-700'}"
                >
                  <div class="w-8 h-8 rounded-xl {p.color} flex items-center justify-center font-bold text-white shadow-lg">{p.icon}</div>
                  <span class="text-xs font-bold tracking-tight {provider === p.id ? 'text-white' : 'text-zinc-400'}">{p.name}</span>
                </button>
              {/each}
            </div>
          </label>
        </div>

        <!-- Connection Details -->
        <div class="space-y-6 pt-4 border-t border-zinc-800/50">
          <span class="text-[10px] font-black text-zinc-500 uppercase tracking-[0.2em] mb-2 block">2. Authentication & Endpoint</span>
          <div class="space-y-4">
            <label class="block">
              <span class="text-xs font-bold text-zinc-400 mb-2 block">API Key</span>
              <input
                type="password"
                bind:value={apiKey}
                class="w-full glass bg-zinc-900/50 px-4 py-3 rounded-xl border-zinc-800 text-sm font-medium focus:ring-2 ring-brand-primary outline-none transition-all"
                placeholder="Paste your {provider} secret key..."
              />
            </label>

            <label class="block">
              <span class="text-xs font-bold text-zinc-400 mb-2 block">Model Name <span class="text-zinc-600 font-normal">(type directly or fetch below)</span></span>
              <input
                bind:value={selectedModel}
                class="w-full glass bg-zinc-900/50 px-4 py-3 rounded-xl border-zinc-800 text-sm font-medium font-mono focus:ring-2 ring-brand-primary outline-none transition-all"
                placeholder="e.g. claude-sonnet-4-20250514, gpt-4o, gemini-2.0-flash..."
              />
            </label>
            {#if provider === 'custom'}
              <label class="block animate-in slide-in-from-top-2">
                <span class="text-xs font-bold text-zinc-400 mb-2 block">Base Endpoint URL</span>
                <input
                  bind:value={endpoint}
                  class="w-full glass bg-zinc-900/50 px-4 py-3 rounded-xl border-zinc-800 text-sm font-medium focus:ring-2 ring-brand-primary outline-none"
                  placeholder="e.g., https://api.groq.com/openai/v1"
                />
              </label>
            {/if}

            <button
              onclick={fetchModels}
              disabled={isLoadingModels || !apiKey}
              class="w-full py-4 rounded-xl border border-zinc-800 bg-white/5 hover:bg-white/10 text-xs font-bold uppercase tracking-widest transition-all disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {#if isLoadingModels}
                <svg class="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                Verifying Connection...
              {:else}
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 21v-5h-5"/></svg>
                Fetch Available Models
              {/if}
            </button>
          </div>
        </div>

        <!-- Model Selection -->
        {#if availableModels.length > 0}
          <div class="space-y-4 pt-6 border-t border-zinc-800/50 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <span class="text-[10px] font-black text-zinc-500 uppercase tracking-[0.2em] mb-2 block">3. Select Authorized Model</span>
            <div class="grid grid-cols-1 gap-2">
              {#each availableModels as m (m)}
                <button
                  onclick={() => selectedModel = m}
                  class="w-full p-4 rounded-xl border text-left transition-all flex items-center justify-between {selectedModel === m ? 'border-brand-primary bg-brand-primary/10' : 'border-zinc-800 bg-zinc-900/30 hover:border-zinc-700'}"
                >
                  <span class="text-xs font-bold {selectedModel === m ? 'text-white' : 'text-zinc-500'}">{m}</span>
                  {#if selectedModel === m}
                    <div class="w-1.5 h-1.5 rounded-full bg-brand-primary shadow-[0_0_8px_rgba(124,58,237,0.5)]"></div>
                  {/if}
                </button>
              {/each}
            </div>
          </div>
        {/if}

        {#if error}
          <div class="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-medium flex items-center gap-2 animate-in fade-in">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>
            {error}
          </div>
        {/if}

        <div class="pt-4 flex justify-end">
          <button
            onclick={handleSave}
            disabled={!selectedModel.trim() || !apiKey.trim()}
            class="btn-primary px-12 py-4 disabled:opacity-30 disabled:cursor-not-allowed shadow-xl shadow-brand-primary/10 transition-all"
          >
            Save Configuration
          </button>
        </div>
      </div>
    </div>

    <!-- Info Panel -->
    <div class="space-y-6">
      <div class="glass p-8 rounded-3xl border-zinc-800 bg-brand-primary/5 relative overflow-hidden">
        <h4 class="text-sm font-bold mb-4 flex items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-brand-primary"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>
          Bring Your Own Key
        </h4>
        <p class="text-xs text-zinc-500 leading-relaxed">
          Zenvra is provider-agnostic. Your keys are used ONLY to generate reports and are never stored on our servers. You get direct market rates with zero markups.
        </p>
      </div>

      <div class="glass p-8 rounded-3xl border-zinc-800 space-y-4">
        <h4 class="text-xs font-bold text-zinc-400 uppercase tracking-widest">Active Policies</h4>
        <div class="space-y-3">
          <div class="flex items-center gap-2 text-xs font-medium text-emerald-500">
            <div class="w-1 h-1 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
            Zero Data Training
          </div>
          <div class="flex items-center gap-2 text-xs font-medium text-zinc-400">
            <div class="w-1.5 h-1.5 rounded-full bg-zinc-700 flex items-center justify-center">
               <div class="w-0.5 h-0.5 rounded-full bg-zinc-500"></div>
            </div>
            Browser Local Storage (plaintext)
          </div>
          <div class="flex items-center gap-2 text-xs font-medium text-zinc-500">
            <div class="w-1 h-1 rounded-full bg-zinc-500"></div>
            Rate Limit (10/min)
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

