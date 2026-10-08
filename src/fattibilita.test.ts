// @vitest-environment node
// src/fattibilita.test.ts
//
// Cosa questo test prova: che le primitive del protocollo della modalità riservata ci sono
// DAVVERO in Node e nel browser e si comportano come il protocollo assume
// (SPEC.md, primitive). Se una sparisce, il resto
// della suite fallirebbe con errori oscuri: qui fallisce con un nome.
import { describe, expect, test } from 'vitest';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { split, combine } from 'shamir-secret-sharing';

describe('fattibilità delle primitive', () => {
  test('X25519 in WebCrypto, privata NON estraibile, usabile da HPKE', async () => {
    const coppia = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
      'deriveBits',
    ])) as CryptoKeyPair;
    await expect(crypto.subtle.exportKey('pkcs8', coppia.privateKey)).rejects.toThrow();
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const info = new TextEncoder().encode('prova').buffer;
    const pt = crypto.getRandomValues(new Uint8Array(32));
    const { ct, enc } = await suite.seal({ recipientPublicKey: coppia.publicKey, info }, pt.buffer);
    expect(enc.byteLength).toBe(32);
    expect(ct.byteLength).toBe(48);
    const aperto = await suite.open({ recipientKey: coppia, enc, info }, ct);
    expect(new Uint8Array(aperto)).toEqual(pt);
  });

  test('Argon2id da libsodium-sumo', async () => {
    const sodium = (await import('libsodium-wrappers-sumo')).default;
    await sodium.ready;
    const sale = new Uint8Array(16);
    const t0 = performance.now();
    const k = sodium.crypto_pwhash(
      32,
      'frase di prova lunga',
      sale,
      3,
      64 * 1024 * 1024,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    const ms = performance.now() - t0;
    expect(k.length).toBe(32);
    console.info(`[fattibilità] Argon2id ops=3 mem=64MiB: ${ms.toFixed(0)} ms`);
  });

  test('Shamir 2-di-3 ricompone con due parti qualsiasi', async () => {
    const r = crypto.getRandomValues(new Uint8Array(32));
    const [a, b, c] = await split(r, 3, 2);
    expect(await combine([a, b])).toEqual(r);
    expect(await combine([b, c])).toEqual(r);
    expect(await combine([a, c])).toEqual(r);
    // La stessa parte due volte NON deve bastare: o la libreria rifiuta, o il risultato è
    // diverso da r. `ricomponi` rifiuta comunque le parti doppie prima di chiamarla.
    let doppia: Uint8Array | null = null;
    try {
      doppia = await combine([a, a]);
    } catch {
      doppia = null;
    }
    if (doppia) expect(doppia).not.toEqual(r);
  });

  test('CompressionStream "deflate" disponibile', async () => {
    const dati = new TextEncoder().encode('x'.repeat(10000));
    const out = await new Response(
      new Blob([dati]).stream().pipeThrough(new CompressionStream('deflate'))
    ).arrayBuffer();
    expect(out.byteLength).toBeLessThan(200);
  });
});
