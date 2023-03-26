/// <reference types="vitest" />
/// <reference types="vite/client" />

import { defineConfig } from 'vite'
import tsconfigPaths from 'vite-tsconfig-paths'

/**
 * Learn more about Vite: https://vitejs.dev/config/
 */
export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    // Use APIs globally like Jest.
    globals: true,

    // Environment.
    environment: 'node',

    // Path to setup files. They will be run before each test file.
    setupFiles: ['./vitest-setup.ts'],

    // Excludes files from test.
    exclude: ['node_modules'],

    // Disable CSS if you don't have tests that relies on it.
    css: false,
  },
})
