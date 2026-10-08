// @vitest-environment node
// src/formato.test.ts
//
// L'ORACOLO dei formati non è il nostro codice: è Node `crypto` (createDecipheriv), che apre la
// busta leggendo i byte agli offset scritti nel protocollo §3. Se il formato derivasse da ciò
// che il nostro codice scrive invece che dalla specifica, questo test lo direbbe.
import { describe, expect, test } from 'vitest';
import { createDecipheriv } from 'node:crypto';
import {
  aad,
  seal,
  unseal,
  cifraAes,
  scriviBusta,
  leggiBusta,
  comprimi,
  decomprimi,
} from './formato';
import { ErroreRiservata } from './errori';
import { a64, ab, da64 } from './bytes';

async function chiave(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', ab(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

describe('AAD canonico (protocollo §3.1)', () => {
  test('prefisso, separatori 0x00, numeri in decimale', () => {
    const b = aad('obj', 'org1', 7);
    expect(Buffer.from(b).toString('latin1')).toBe('dcam.riservata.v1\0obj\0org1\x007');
  });
  test('un campo con 0x00 è rifiutato', () => {
    expect(() => aad('a\0b')).toThrow(ErroreRiservata);
  });
  test('un numero negativo o non intero è rifiutato', () => {
    expect(() => aad(-1)).toThrow();
    expect(() => aad(1.5)).toThrow();
  });
});

describe('sigillo DCS1 (protocollo §3.4)', () => {
  test('Node crypto lo apre leggendo gli offset della specifica', async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const k = await chiave(raw);
    const a = aad('person', 'org1', 'u1');
    const pt = new TextEncoder().encode('privata pkcs8 finta');
    const busta = await seal(k, pt, a);
    expect(Buffer.from(busta.subarray(0, 4)).toString()).toBe('DCS1');
    const nonce = busta.subarray(4, 16);
    const ct = busta.subarray(16, busta.length - 16);
    const tag = busta.subarray(busta.length - 16);
    const d = createDecipheriv('aes-256-gcm', raw, nonce);
    d.setAAD(a);
    d.setAuthTag(tag);
    const out = Buffer.concat([d.update(ct), d.final()]);
    expect(out.toString()).toBe('privata pkcs8 finta');
  });
  test('AAD diverso → ErroreRiservata("apertura"), non contenuto sbagliato', async () => {
    const k = await chiave(crypto.getRandomValues(new Uint8Array(32)));
    const busta = await seal(k, new Uint8Array([1, 2, 3]), aad('person', 'org1', 'u1'));
    await expect(unseal(k, busta, aad('person', 'org1', 'u2'))).rejects.toMatchObject({
      codice: 'apertura',
    });
  });
  test('un byte cambiato in qualunque punto → errore', async () => {
    const k = await chiave(crypto.getRandomValues(new Uint8Array(32)));
    const a = aad('x');
    const busta = await seal(k, new Uint8Array(40), a);
    for (let i = 4; i < busta.length; i++) {
      const rotta = busta.slice();
      rotta[i] ^= 1;
      await expect(unseal(k, rotta, a)).rejects.toBeInstanceOf(ErroreRiservata);
    }
  });
  test('magic sbagliato → ErroreRiservata("formato")', async () => {
    const k = await chiave(crypto.getRandomValues(new Uint8Array(32)));
    const busta = await seal(k, new Uint8Array(4), aad('x'));
    busta[0] = 0x58;
    await expect(unseal(k, busta, aad('x'))).rejects.toMatchObject({ codice: 'formato' });
  });
});

describe('busta generica', () => {
  test('intestazione, nonce e cifrato tornano agli offset scritti', async () => {
    const k = await chiave(crypto.getRandomValues(new Uint8Array(32)));
    const { nonce, cifrato } = await cifraAes(k, new Uint8Array([9]), aad('x'));
    const intest = new Uint8Array([1, 0, 0, 0, 5]);
    const b = scriviBusta('DCR1', intest, nonce, cifrato);
    expect(b.length).toBe(4 + 5 + 12 + 1 + 16);
    const l = leggiBusta('DCR1', b, 5);
    expect(l.intestazione).toEqual(intest);
    expect(l.nonce).toEqual(nonce);
    expect(l.cifrato).toEqual(cifrato);
  });
  test('busta troppo corta → formato', () => {
    expect(() => leggiBusta('DCR1', new Uint8Array(10), 5)).toThrow(ErroreRiservata);
  });
});

describe('codec', () => {
  test('comprimi/decomprimi tornano uguali', async () => {
    const dati = new TextEncoder().encode('<svg>' + 'M 0 0 L 10 10 '.repeat(5000) + '</svg>');
    const c = await comprimi(dati);
    expect(c.length).toBeLessThan(dati.length / 10);
    expect(await decomprimi(c)).toEqual(dati);
  });
});

describe('base64url', () => {
  test('senza riempimento, ritorno esatto per ogni lunghezza 0..40', () => {
    for (let n = 0; n <= 40; n++) {
      const b = crypto.getRandomValues(new Uint8Array(n));
      const s = a64(b);
      expect(s).not.toMatch(/[+/=]/);
      expect(da64(s)).toEqual(b);
      expect(s).toBe(Buffer.from(b).toString('base64url'));
    }
  });
});
