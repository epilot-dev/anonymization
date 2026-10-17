import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // mcp-proxy/ is a separate package with its own deps and test run
    exclude: [...configDefaults.exclude, 'mcp-proxy/**'],
  },
});
