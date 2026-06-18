import { writable } from 'svelte/store';

const stored = typeof localStorage !== 'undefined' ? localStorage.getItem('argus_theme') : 'dark';
export const theme = writable(stored || 'dark');

theme.subscribe((v) => {
  if (typeof document !== 'undefined') document.documentElement.setAttribute('data-theme', v);
  if (typeof localStorage !== 'undefined') localStorage.setItem('argus_theme', v);
});
