<script lang="ts">
  import "../app.css";
  import { page } from "$app/state";
  let { children } = $props();

  const navItems = [
    { name: "Dashboard", href: "/", icon: "layout-grid" },
    { name: "Scan Code", href: "/scan", icon: "search" },
    { name: "Scan History", href: "/history", icon: "clock" },
    { name: "CVE Settings", href: "/settings/cve", icon: "database" },
    { name: "AI Settings", href: "/settings/ai", icon: "sparkles" },
  ];
</script>

<svelte:head>
  <title>Zenvra — AI Code Security Scanner</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet" />
</svelte:head>

<div class="flex h-screen overflow-hidden bg-background">
  <!-- Sidebar -->
  <aside class="w-64 border-r border-border bg-surface/30 backdrop-blur-xl flex flex-col">
    <div class="p-6">
      <a href="/" class="flex items-center gap-2 group">
        <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-primary to-brand-secondary flex items-center justify-center text-white shadow-lg shadow-brand-primary/20 group-hover:scale-110 transition-transform duration-300">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/></svg>
        </div>
        <span class="text-xl font-bold font-outfit tracking-tight">Zenvra</span>
      </a>
    </div>

    <nav class="flex-1 px-4 py-4 space-y-1">
      {#each navItems as item}
        <a 
          href={item.href} 
          class="flex items-center gap-3 px-4 py-2.5 rounded-xl transition-all duration-200 group {page.url.pathname === item.href ? 'bg-brand-primary/10 text-brand-primary' : 'hover:bg-white/5 text-zinc-400 hover:text-zinc-100'}"
        >
          <span class="w-1.5 h-1.5 rounded-full bg-brand-primary transition-all duration-300 {page.url.pathname === item.href ? 'scale-100 opacity-100' : 'scale-0 opacity-0 group-hover:scale-100 group-hover:opacity-50'}"></span>
          <span class="font-medium">{item.name}</span>
        </a>
      {/each}
    </nav>

    <div class="p-4 border-t border-border">
      <div class="p-4 glass-card bg-zinc-800/20 backdrop-blur-sm rounded-xl">
        <p class="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Usage Plan</p>
        <p class="text-sm font-medium mb-1">Free Tier</p>
        <div class="w-full bg-zinc-800 h-1.5 rounded-full overflow-hidden mt-2">
          <div class="bg-brand-primary w-2/5 h-full rounded-full shadow-[0_0_8px_rgba(236,72,153,0.5)]"></div>
        </div>
        <p class="text-[10px] text-zinc-500 mt-2">4/10 scans remaining</p>
      </div>
    </div>
  </aside>

  <!-- Main Content -->
  <main class="flex-1 flex flex-col overflow-hidden">
    <!-- Header -->
    <header class="h-16 border-b border-border flex items-center justify-between px-8 bg-surface/10">
      <div class="text-sm text-zinc-500 font-medium whitespace-nowrap overflow-hidden text-ellipsis max-w-md">
        {#if page.url.pathname === "/"}
          Welcome back, <span class="text-zinc-200">vibe coder</span>
        {:else}
          {navItems.find(i => i.href === page.url.pathname)?.name || "Page"}
        {/if}
      </div>
      
      <div class="flex items-center gap-4">
        <button 
          aria-label="Notifications"
          class="w-9 h-9 flex items-center justify-center rounded-xl glass hover:bg-white/5 transition-colors"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>
        </button>
        <div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-brand-secondary to-blue-500 flex items-center justify-center text-white font-bold text-sm shadow-lg shadow-blue-500/20">
          J
        </div>
      </div>
    </header>

    <!-- Page Content -->
    <div class="flex-1 overflow-y-auto p-8 custom-scrollbar">
      {@render children()}
    </div>
  </main>
</div>

<style>
  :global(.custom-scrollbar::-webkit-scrollbar) {
    width: 8px;
  }
  :global(.custom-scrollbar::-webkit-scrollbar-track) {
    background: transparent;
  }
  :global(.custom-scrollbar::-webkit-scrollbar-thumb) {
    background: #27272a;
    border-radius: 10px;
    border: 2px solid #09090b;
  }
  :global(.custom-scrollbar::-webkit-scrollbar-thumb:hover) {
    background: #3f3f46;
  }
</style>
