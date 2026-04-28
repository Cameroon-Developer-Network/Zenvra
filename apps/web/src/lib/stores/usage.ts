import { writable } from 'svelte/store';
import { getHistory } from '$lib/api';

export const scanCount = writable<number>(0);

export async function refreshScanCount() {
  try {
    const history = await getHistory();
    scanCount.set(history.length);
  } catch (e) {
    console.error('Failed to refresh scan count:', e);
  }
}
