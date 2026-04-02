<script lang="ts">
  import '../app.css';
  let { children } = $props();
</script>

<svelte:head>
  <title>Zenvra — Ship fast. Ship safe.</title>
  <meta name="description" content="AI-powered code vulnerability scanner. Find CVEs in seconds, get plain-English fixes instantly." />
</svelte:head>

{@render children()}
