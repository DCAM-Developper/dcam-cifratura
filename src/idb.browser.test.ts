// src/idb.browser.test.ts — solo nel browser (Chromium e WebKit).
// Le coppie della postazione (ECDH per le chiusure, ECDSA per le firme, §2) vivono in IndexedDB
// come CryptoKey NON estraibili: qui si salvano, si rileggono da una connessione nuova e si usano.
// (Su WebKit una X25519 salvata tornava null: per questo il protocollo usa P-256.)
import { expect, test } from 'vitest';
import { generaCoppia, pubblicaRaw } from './chiavi';
import { generaCoppiaFirma } from './firma';
import { ab } from './bytes';

const apri = () =>
  new Promise<IDBDatabase>((ok, ko) => {
    const r = indexedDB.open(`dcam-prova-${Math.random()}`, 1);
    r.onupgradeneeded = () => r.result.createObjectStore('k');
    r.onsuccess = () => ok(r.result);
    r.onerror = () => ko(r.error);
  });
const riapri = (nome: string) =>
  new Promise<IDBDatabase>((ok, ko) => {
    const r = indexedDB.open(nome, 1);
    r.onsuccess = () => ok(r.result);
    r.onerror = () => ko(r.error);
  });
const op = <T>(
  db: IDBDatabase,
  m: 'readonly' | 'readwrite',
  f: (s: IDBObjectStore) => IDBRequest
) =>
  new Promise<T>((ok, ko) => {
    const r = f(db.transaction('k', m).objectStore('k'));
    r.onsuccess = () => ok(r.result as T);
    r.onerror = () => ko(r.error);
  });

test('coppie ECDH ed ECDSA P-256 non estraibili sopravvivono a IndexedDB e si usano', async () => {
  const dh = await generaCoppia(false);
  const fi = await generaCoppiaFirma(false);
  await expect(crypto.subtle.exportKey('pkcs8', fi.privateKey)).rejects.toThrow();
  const db = await apri();
  const nome = db.name;
  await op(db, 'readwrite', s => s.put({ dh, fi }, 'postazione'));
  db.close();
  const db2 = await riapri(nome);
  const r = await op<{ dh: CryptoKeyPair; fi: CryptoKeyPair } | undefined>(db2, 'readonly', s =>
    s.get('postazione')
  );
  db2.close();
  expect(r?.fi?.privateKey).toBeTruthy();
  expect(r?.dh?.privateKey).toBeTruthy();
  expect(r!.fi.privateKey.extractable).toBe(false);
  const m = new TextEncoder().encode('transizione');
  const alg = { name: 'ECDSA', hash: 'SHA-256' };
  const sig = await crypto.subtle.sign(alg, r!.fi.privateKey, ab(m));
  expect(sig.byteLength).toBe(64);
  expect(await crypto.subtle.verify(alg, fi.publicKey, sig, ab(m))).toBe(true);
  const altra = await generaCoppia(false);
  const bit = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: altra.publicKey },
    r!.dh.privateKey,
    256
  );
  expect(bit.byteLength).toBe(32);
  expect((await pubblicaRaw(r!.fi.publicKey)).length).toBe(65);
});
