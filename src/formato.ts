// src/formato.ts
// Formati del protocollo v2 — protocollo §3 (SPEC.md).
import { ab, concatena, casuali } from './bytes';
import { ErroreRiservata } from './errori';

export const PREFISSO_AAD = 'dcam.riservata.v2';
export type Magic = 'DCR2' | 'DCS2' | 'DCM2';
const NONCE = 12;
const TAG = 16;
const enc = new TextEncoder();

export function aad(...campi: Array<string | number>): Uint8Array {
  const testi = campi.map(c => {
    if (typeof c === 'number') {
      if (!Number.isSafeInteger(c) || c < 0) {
        throw new ErroreRiservata('formato', `AAD: numero non valido (${c})`);
      }
      return String(c);
    }
    if (c.includes('\u0000')) throw new ErroreRiservata('formato', 'AAD: campo con byte 0x00');
    return c;
  });
  return enc.encode([PREFISSO_AAD, ...testi].join('\u0000'));
}

export function scriviBusta(
  magic: Magic,
  intestazione: Uint8Array,
  nonce: Uint8Array,
  cifrato: Uint8Array
): Uint8Array {
  return concatena(enc.encode(magic), intestazione, nonce, cifrato);
}

export function leggiBusta(
  magic: Magic,
  buf: Uint8Array,
  lungIntestazione: number
): { intestazione: Uint8Array; nonce: Uint8Array; cifrato: Uint8Array } {
  const minimo = 4 + lungIntestazione + NONCE + TAG;
  if (buf.length < minimo) throw new ErroreRiservata('formato', `busta ${magic} troppo corta`);
  const m = new TextDecoder().decode(buf.subarray(0, 4));
  if (m !== magic) throw new ErroreRiservata('formato', `attesa busta ${magic}, trovata «${m}»`);
  const i = 4 + lungIntestazione;
  return {
    intestazione: buf.subarray(4, i),
    nonce: buf.subarray(i, i + NONCE),
    cifrato: buf.subarray(i + NONCE),
  };
}

export async function cifraAes(
  k: CryptoKey,
  pt: Uint8Array,
  aadB: Uint8Array
): Promise<{ nonce: Uint8Array; cifrato: Uint8Array }> {
  const nonce = casuali(NONCE);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ab(nonce), additionalData: ab(aadB), tagLength: 128 },
    k,
    ab(pt)
  );
  return { nonce, cifrato: new Uint8Array(ct) };
}

export async function decifraAes(
  k: CryptoKey,
  nonce: Uint8Array,
  cifrato: Uint8Array,
  aadB: Uint8Array
): Promise<Uint8Array> {
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ab(nonce), additionalData: ab(aadB), tagLength: 128 },
      k,
      ab(cifrato)
    );
    return new Uint8Array(pt);
  } catch {
    throw new ErroreRiservata(
      'apertura',
      'il contenuto non si apre con questa chiave o è stato alterato'
    );
  }
}

export async function seal(k: CryptoKey, pt: Uint8Array, aadB: Uint8Array): Promise<Uint8Array> {
  const { nonce, cifrato } = await cifraAes(k, pt, aadB);
  return scriviBusta('DCS2', new Uint8Array(0), nonce, cifrato);
}

export async function unseal(
  k: CryptoKey,
  busta: Uint8Array,
  aadB: Uint8Array
): Promise<Uint8Array> {
  const { nonce, cifrato } = leggiBusta('DCS2', busta, 0);
  return decifraAes(k, nonce, cifrato, aadB);
}

async function attraverso(
  b: Uint8Array,
  t: CompressionStream | DecompressionStream,
  tetto = Infinity
): Promise<Uint8Array> {
  const lettore = new Blob([ab(b)]).stream().pipeThrough(t).getReader();
  const pezzi: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await lettore.read();
    if (done) break;
    n += value.length;
    if (n > tetto) {
      await lettore.cancel();
      throw new ErroreRiservata('formato', `contenuto decompresso oltre ${tetto} byte`);
    }
    pezzi.push(value);
  }
  return concatena(...pezzi);
}

/** Tetto all'uscita di `decomprimi` (protocollo §3.2): 256 MiB. */
export const TETTO_DECOMPRESSO = 256 * 1024 * 1024;
export const comprimi = (b: Uint8Array) => attraverso(b, new CompressionStream('deflate'));
export const decomprimi = (b: Uint8Array, tetto = TETTO_DECOMPRESSO) =>
  attraverso(b, new DecompressionStream('deflate'), tetto);
