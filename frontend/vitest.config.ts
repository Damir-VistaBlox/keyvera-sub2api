import { defineConfig } from 'vitest/config'
import { resolve } from 'path'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      'vue-i18n': 'vue-i18n/dist/vue-i18n.runtime.esm-bundler.js'
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/__tests__/setup.ts'],
    include: ['src/**/*.{test,spec}.{js,ts,jsx,tsx}'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.{js,ts,vue}'],
      exclude: [
        'node_modules',
        'src/**/*.d.ts',
        'src/**/*.spec.ts',
        'src/**/*.test.ts',
        'src/main.ts'
      ],
      // Floor set just below the actual suite coverage (69.28/69.99/43.61/69.28
      // as of the fix landing in #11) now that CI enforces this instead of
      // silently ignoring it. Ratchet these up as coverage improves; this is
      // a regression floor, not an aspirational target.
      thresholds: {
        global: {
          statements: 68,
          branches: 68,
          functions: 42,
          lines: 68
        }
      }
    }
  }
})
