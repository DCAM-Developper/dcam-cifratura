// src/testo.ts
// Crockford base32 (https://www.crockford.com/base32.html): niente I, L, O, U; lettura tollerante.
// È una CODIFICA per stampare e digitare chiavi, non crittografia.
import { ErroreRiservata } from './errori';

const ALFABETO = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function aBase32(b: Uint8Array): string {
  let bit = 0;
  let valore = 0;
  let out = '';
  for (const byte of b) {
    valore = (valore << 8) | byte;
    bit += 8;
    while (bit >= 5) {
      out += ALFABETO[(valore >>> (bit - 5)) & 31];
      bit -= 5;
    }
  }
  if (bit > 0) out += ALFABETO[(valore << (5 - bit)) & 31];
  return out;
}

export function normalizza(s: string): string {
  return s.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
}

export function daBase32(s: string, byte: number): Uint8Array {
  const n = normalizza(s);
  const out = new Uint8Array(byte);
  let bit = 0;
  let valore = 0;
  let o = 0;
  for (const ch of n) {
    const v = ALFABETO.indexOf(ch);
    if (v < 0) throw new ErroreRiservata('formato', `carattere non valido «${ch}»`);
    valore = (valore << 5) | v;
    bit += 5;
    if (bit >= 8) {
      if (o < byte) out[o++] = (valore >>> (bit - 8)) & 255;
      bit -= 8;
    }
  }
  if (o !== byte) throw new ErroreRiservata('formato', `attesi ${byte} byte, letti ${o}`);
  return out;
}

export function aGruppi(s: string, n = 4): string {
  return s.match(new RegExp(`.{1,${n}}`, 'g'))?.join('-') ?? '';
}

export function simboliCasuali(n: number): string {
  // 32 simboli = 5 bit esatti per byte casuale mascherato: nessuna distorsione.
  const r = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(r, x => ALFABETO[x & 31]).join('');
}
