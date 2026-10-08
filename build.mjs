// Build: esbuild produce un solo modulo ESM (dipendenze esterne), tsc produce i tipi.
import { build } from 'esbuild';
await build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  platform: 'neutral',
  target: 'es2022',
  outfile: 'dist/index.js',
  sourcemap: true,
  external: ['@hpke/core', 'libsodium-wrappers-sumo', 'shamir-secret-sharing'],
  legalComments: 'inline',
});
