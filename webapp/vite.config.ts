import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: { host: true, strictPort: false },
  build: { target: 'es2020', outDir: 'dist', sourcemap: true }
});
