import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

// Static demo build (`npm run build:demo` → dist-demo/): the read-only viewer
// (SharedView) plus every snapshot of eval/demo/ (written by
// eval/demo_export.py). No backend: any static host serves it, from any path
// (base './'). The app build (vite.config.js) is untouched by this file.
const here = fileURLToPath(new URL('.', import.meta.url))
const snapshots = join(here, '..', 'eval', 'demo')
const outDir = join(here, 'dist-demo')
const files = existsSync(snapshots)
  ? readdirSync(snapshots).filter(f => /^[a-z0-9][a-z0-9_-]*\.json$/.test(f)).sort()
  : []

function copySnapshots() {
  return {
    name: 'bounce-demo-snapshots',
    apply: 'build',
    closeBundle() {
      mkdirSync(join(outDir, 'data'), { recursive: true })
      for (const f of files) copyFileSync(join(snapshots, f), join(outDir, 'data', f))
    },
  }
}

export default defineConfig({
  root: join(here, 'demo'),
  base: './',
  publicDir: join(here, 'public'),
  plugins: [react(), copySnapshots()],
  define: { __DEMO_CASES__: JSON.stringify(files.map(f => f.slice(0, -'.json'.length))) },
  build: { outDir, emptyOutDir: true },
})
