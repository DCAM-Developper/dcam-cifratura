// Prova che due file TypeScript differiscono SOLO nei commenti e negli spazi: li trasforma con
// esbuild (tipi e commenti via, spazi minimizzati) e confronta il JavaScript risultante.
// Uso: node strumenti/stesso-codice.mjs <a.ts> <b.ts>   → uscita 0 se uguali, 1 se diversi.
import { transformSync } from 'esbuild';
import { readFileSync } from 'node:fs';

const js = f =>
  transformSync(readFileSync(f, 'utf8'), { loader: 'ts', legalComments: 'none', minifyWhitespace: true }).code;
const [a, b] = process.argv.slice(2);
if (!a || !b) {
  console.error('uso: node strumenti/stesso-codice.mjs <a.ts> <b.ts>');
  process.exit(2);
}
const uguali = js(a) === js(b);
console.log(uguali ? 'stesso codice' : 'CODICE DIVERSO');
process.exit(uguali ? 0 : 1);
