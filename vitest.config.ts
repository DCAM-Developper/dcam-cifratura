import { defineConfig } from 'vitest/config';

// Gli stessi test girano due volte: in Node (WebCrypto e CompressionStream globali di Node)
// e in Chromium vero (WebCrypto e CompressionStream del browser). I test che usano
// `node:crypto` / `node:zlib` come oracolo indipendente girano solo in Node.
const SOLO_NODE = ['src/formato.test.ts', 'src/oggetto.test.ts'];

export default defineConfig({
  test: {
    projects: [
      {
        test: { name: 'node', environment: 'node', include: ['src/**/*.test.ts', 'vettori/**/*.test.ts'], exclude: ['src/**/*.browser.test.ts'] },
      },
      {
        test: {
          name: 'browser',
          include: ['src/**/*.test.ts', 'vettori/**/*.test.ts'],
          exclude: SOLO_NODE,
          browser: {
            enabled: true,
            provider: 'playwright',
            headless: true,
            instances: [{ browser: 'chromium' }, { browser: 'webkit' }],
          },
        },
      },
    ],
  },
});
