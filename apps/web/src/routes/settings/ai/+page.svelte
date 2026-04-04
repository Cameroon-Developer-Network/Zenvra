<script lang="ts">
  import { onMount } from "svelte";

  let provider = $state("anthropic");
  let model = $state("claude-sonnet-4-20250514");
  let apiKey = $state("");
  let endpoint = $state("");

  const providers = [
    { id: "anthropic", name: "Anthropic", models: ["claude-sonnet-4-20250514", "claude-opus-20240229", "claude-haiku-20240307"], color: "bg-[#7c3aed]" },
    { id: "openai", name: "OpenAI", models: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"], color: "bg-[#10a37f]" },
    { id: "google", name: "Google Gemini", models: ["gemini-2.0-flash", "gemini-1.5-pro-latest"], color: "bg-[#4285f4]" },
    { id: "custom", name: "Custom Provider", models: ["openai-compatible"], color: "bg-zinc-600" }
  ];

  const handleSave = () => {
     // Local storage for now, full backend sync in the next phase
     localStorage.setItem('zenvra_ai_provider', provider);
     localStorage.setItem('zenvra_ai_model', model);
     localStorage.setItem('zenvra_ai_api_key', apiKey);
     alert("Configuration saved locally. Default models will now use these settings.");
  };

  onMount(() => {
    provider = localStorage.getItem('zenvra_ai_provider') || "anthropic";
    model = localStorage.getItem('zenvra_ai_model') || "claude-sonnet-4-20250514";
    apiKey = localStorage.getItem('zenvra_ai_api_key') || "";
  });
</script>

<div class="max-w-4xl mx-auto space-y-8">
  <div class="flex items-end justify-between">
    <div>
      <h1 class="text-3xl font-bold font-outfit mb-2">AI Configuration</h1>
      <p class="text-zinc-500">Configure the AI models responsible for vulnerability explanations and fix suggestions.</p>
    </div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
    <!-- Configuration Form -->
    <div class="lg:col-span-2 space-y-6">
      <div class="glass p-8 rounded-3xl border-zinc-800 space-y-6">
        <div class="space-y-4">
          <label class="block">
            <span class="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-2 block">AI Provider</span>
            <div class="grid grid-cols-2 gap-3">
              {#each providers as p}
                <button 
                  onclick={() => { provider = p.id; model = p.models[0]; }}
                  class="p-4 rounded-2xl border transition-all flex flex-col gap-2 items-start text-left {provider === p.id ? 'border-brand-primary bg-brand-primary/5' : 'border-zinc-800 bg-zinc-900/50 hover:bg-zinc-800 hover:border-zinc-700'}"
                >
                  <div class="w-2 h-2 rounded-full {p.color}"></div>
                  <span class="text-sm font-bold {provider === p.id ? 'text-white' : 'text-zinc-400'}">{p.name}</span>
                </button>
              {/each}
            </div>
          </label>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label class="block">
              <span class="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-2 block">Preferred Model</span>
              <select bind:value={model} class="w-full glass bg-zinc-900 px-4 py-3 rounded-xl border-zinc-800 text-sm font-medium focus:ring-2 ring-brand-primary outline-none">
                {#each (providers.find(p => p.id === provider)?.models || []) as m}
                  <option value={m}>{m}</option>
                {/each}
              </select>
            </label>

            <label class="block">
              <span class="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-2 block">API Key</span>
              <input 
                type="password"
                bind:value={apiKey} 
                class="w-full glass bg-zinc-900 px-4 py-3 rounded-xl border-zinc-800 text-sm font-medium focus:ring-2 ring-brand-primary outline-none" 
                placeholder="sk-ant-... or sk-..."
              />
            </label>
          </div>

          {#if provider === 'custom'}
             <label class="block slide-in-from-top-2 animate-in duration-300">
              <span class="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-2 block">Base Endpoint</span>
              <input 
                bind:value={endpoint} 
                class="w-full glass bg-zinc-900 px-4 py-3 rounded-xl border-zinc-800 text-sm font-medium focus:ring-2 ring-brand-primary outline-none" 
                placeholder="https://api.groq.com/openai/v1"
              />
            </label>
          {/if}
        </div>

        <div class="pt-4 flex justify-end">
          <button onclick={handleSave} class="btn-primary px-8">Save Configuration</button>
        </div>
      </div>
    </div>

    <!-- Info Panel -->
    <div class="space-y-6">
      <div class="glass p-8 rounded-3xl border-zinc-800 bg-brand-primary/5 relative overflow-hidden group">
        <h4 class="text-sm font-bold mb-4 flex items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-brand-primary"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>
          Bring Your Own Key
        </h4>
        <p class="text-xs text-zinc-500 leading-relaxed">
          Zenvra is built to be provider-agnostic. We don't mark up AI costs—simply bring your own API key to get start-of-the-art security analysis at market rates.
        </p>
      </div>

      <div class="glass p-8 rounded-3xl border-zinc-800 space-y-4">
         <h4 class="text-xs font-bold text-zinc-400 uppercase tracking-widest">Active Policies</h4>
         <div class="space-y-3">
           <div class="flex items-center gap-2 text-xs font-medium text-emerald-500">
             <div class="w-1 h-1 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
             Zero Data Training
           </div>
           <div class="flex items-center gap-2 text-xs font-medium text-zinc-500">
             <div class="w-1 h-1 rounded-full bg-zinc-500"></div>
             Streaming Enabled
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
