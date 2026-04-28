/**
 * Singleton AI configuration store.
 *
 * Reads from localStorage exactly once when the module is first imported
 * in the browser. Both the settings page and the scan page share this
 * instance so state is always consistent — no onMount race conditions.
 */
import { browser } from '$app/environment';

function createAiConfigStore() {
  // Default to empty — users must explicitly configure via Settings.
  let provider = $state(browser ? (localStorage.getItem('zenvra_ai_provider') ?? 'anthropic') : 'anthropic');
  let model    = $state(browser ? (localStorage.getItem('zenvra_ai_model')    ?? '') : '');
  let apiKey   = $state(browser ? (localStorage.getItem('zenvra_ai_api_key')  ?? '') : '');
  let endpoint = $state(browser ? (localStorage.getItem('zenvra_ai_endpoint') ?? '') : '');

  const isConfigured = $derived(!!model && !!apiKey);
  const apiBaseUrl = browser ? (import.meta.env.PUBLIC_API_URL || 'http://localhost:8080') : 'http://localhost:8080';

  /** Persist changes to both reactive state and localStorage atomically. */
  function save(p: string, m: string, key: string, ep: string): void {
    provider = p;
    model    = m;
    apiKey   = key;
    endpoint = ep;

    if (browser) {
      localStorage.setItem('zenvra_ai_provider', p);
      localStorage.setItem('zenvra_ai_model',    m);
      localStorage.setItem('zenvra_ai_api_key',  key);
      if (ep) localStorage.setItem('zenvra_ai_endpoint', ep);
      else    localStorage.removeItem('zenvra_ai_endpoint');
    }
  }

  return {
    get provider()     { return provider; },
    get model()        { return model; },
    get apiKey()       { return apiKey; },
    get endpoint()     { return endpoint; },
    get isConfigured() { return isConfigured; },
    get apiBaseUrl()   { return apiBaseUrl; },
    save,
  };
}

export const aiConfig = createAiConfigStore();
