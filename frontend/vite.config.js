import { defineConfig } from 'vite';
import { sveltekit } from '@sveltejs/kit/vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    proxy: {
      '/api': 'http://localhost:8443',
      '/metrics': 'http://localhost:8443',
      '/ws': {
        target: 'ws://localhost:8443',
        ws: true
      }
    }
  }
});
