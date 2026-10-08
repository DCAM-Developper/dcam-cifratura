// src/chiavi.ts
// Chiavi del protocollo v1 — protocollo §2, §3.3, §3.4, §4.3, §5.
// Curva: P-256 e non X25519 — su WebKit una CryptoKey X25519 salvata in IndexedDB torna null
// (misurato nello studio di fattibilità).
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { split, combine } from 'shamir-secret-sharing';
import { ab, a64, da64, casuali, concatena } from './bytes';
import { aad, seal, unseal } from './formato';
import { ErroreRiservata } from './errori';
import { simboliCasuali, normalizza } from './testo';
import { CUSTODIA_PUBBLICA } from './custodia';

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

/** ECDH P-256 per tutte le coppie del protocollo (persone, postazioni, recupero, custodia). */
export const CURVA = { name: 'ECDH', namedCurve: 'P-256' } as const;
/** enc di DHKEM(P-256): punto non compresso, 65 byte. Chiusura = enc || 32 byte cifrati || tag 16. */
const ENC = 65;

export function generaChiaveEpoca(): Uint8Array {
  return casuali(32);
}

async function hkdfAes(
  ikm: Uint8Array,
  info: string,
  salt: Uint8Array = new Uint8Array(0)
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', ab(ikm), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: ab(salt), info: new TextEncoder().encode(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export const chiaveDati = (e: Uint8Array) => hkdfAes(e, 'dcam.riservata.v1.data');
export const chiaveElenco = (e: Uint8Array) => hkdfAes(e, 'dcam.riservata.v1.manifest');

export async function generaCoppia(estraibile: boolean): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(CURVA, estraibile, ['deriveBits'])) as CryptoKeyPair;
}
export async function pubblicaRaw(k: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', k));
}
export async function importaPubblica(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', ab(raw), CURVA, true, []);
}

export type ContestoChiusura = {
  orgId: string;
  epoch: number;
  kind: 'person' | 'device' | 'recovery';
  id: string;
};
const infoChiusura = (c: ContestoChiusura) =>
  ab(aad('wrap', 'epoch', c.orgId, c.epoch, c.kind, c.id));

export async function chiudiPer(
  chiave32: Uint8Array,
  pub: Uint8Array,
  c: ContestoChiusura
): Promise<Uint8Array> {
  const { ct, enc } = await suite.seal(
    { recipientPublicKey: await importaPubblica(pub), info: infoChiusura(c) },
    ab(chiave32)
  );
  return concatena(new Uint8Array(enc), new Uint8Array(ct));
}

export async function apriPer(
  chiusa: Uint8Array,
  coppia: CryptoKeyPair,
  c: ContestoChiusura
): Promise<Uint8Array> {
  if (chiusa.length !== ENC + 48)
    throw new ErroreRiservata('formato', 'chiusura di lunghezza inattesa');
  try {
    const pt = await suite.open(
      { recipientKey: coppia, enc: ab(chiusa.subarray(0, ENC)), info: infoChiusura(c) },
      ab(chiusa.subarray(ENC))
    );
    return new Uint8Array(pt);
  } catch {
    throw new ErroreRiservata(
      'apertura',
      "la chiave d'azienda non si apre con questa postazione o persona"
    );
  }
}

// ── frase → chiave (Argon2id, protocollo §2.1) ─────────────────────────
export type ParametriKdf = { alg: 'argon2id13'; ops: number; mem: number; salt: string };
export const PARAMETRI_KDF = { alg: 'argon2id13', ops: 3, mem: 64 * 1024 * 1024 } as const;
export const FRASE_MINIMA = 12;

export function nuoviParametri(): ParametriKdf {
  return { ...PARAMETRI_KDF, salt: a64(casuali(16)) };
}

export async function chiaveDaFrase(frase: string, p: ParametriKdf): Promise<CryptoKey> {
  if (p.alg !== 'argon2id13') throw new ErroreRiservata('formato', `KDF sconosciuto ${p.alg}`);
  const sodium = (await import('libsodium-wrappers-sumo')).default;
  await sodium.ready;
  const raw = sodium.crypto_pwhash(
    32,
    new TextEncoder().encode(frase.normalize('NFC')),
    da64(p.salt),
    p.ops,
    p.mem,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
  try {
    return await crypto.subtle.importKey('raw', ab(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
  } finally {
    sodium.memzero(raw);
  }
}

// ── persona ───────────────────────────────────────────────────────────
export type RecordPersona = { pubKey: string; sealedPriv: string; kdf: ParametriKdf };

export async function creaPersona(
  orgId: string,
  userId: string,
  frase: string,
  p: ParametriKdf = nuoviParametri()
): Promise<{ record: RecordPersona; coppia: CryptoKeyPair }> {
  if (frase.normalize('NFC').length < FRASE_MINIMA) {
    throw new ErroreRiservata('frase', `la frase deve avere almeno ${FRASE_MINIMA} caratteri`);
  }
  const estraibile = await generaCoppia(true);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', estraibile.privateKey));
  const kp = await chiaveDaFrase(frase, p);
  const sealedPriv = await seal(kp, pkcs8, aad('person', orgId, userId));
  pkcs8.fill(0);
  const pub = await pubblicaRaw(estraibile.publicKey);
  return {
    record: { pubKey: a64(pub), sealedPriv: a64(sealedPriv), kdf: p },
    coppia: await coppiaDaPkcs8(await crypto.subtle.exportKey('pkcs8', estraibile.privateKey), pub),
  };
}

async function coppiaDaPkcs8(pkcs8: ArrayBuffer, pub: Uint8Array): Promise<CryptoKeyPair> {
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, CURVA, false, ['deriveBits']);
  return { privateKey, publicKey: await importaPubblica(pub) };
}

export async function apriPersona(
  orgId: string,
  userId: string,
  frase: string,
  r: RecordPersona
): Promise<CryptoKeyPair> {
  const kp = await chiaveDaFrase(frase, r.kdf);
  let pkcs8: Uint8Array;
  try {
    pkcs8 = await unseal(kp, da64(r.sealedPriv), aad('person', orgId, userId));
  } catch (e) {
    if (e instanceof ErroreRiservata && e.codice === 'apertura') {
      throw new ErroreRiservata('frase', 'frase riservata sbagliata');
    }
    throw e;
  }
  return coppiaDaPkcs8(ab(pkcs8), da64(r.pubKey));
}

// ── recupero (protocollo §5) ──────────────────────────────────────────
export type Recupero = {
  R: Uint8Array;
  pubKey: Uint8Array;
  sealedPriv: Uint8Array;
  parti: [Uint8Array, Uint8Array, Uint8Array];
};
const kekRecupero = (R: Uint8Array) => hkdfAes(R, 'dcam.riservata.v1.recovery-kek');

export async function creaRecupero(orgId: string): Promise<Recupero> {
  const R = casuali(32);
  const coppia = await generaCoppia(true);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', coppia.privateKey));
  const sealedPriv = await seal(await kekRecupero(R), pkcs8, aad('recovery', orgId));
  pkcs8.fill(0);
  const [a, b, c] = await split(R, 3, 2);
  return { R, pubKey: await pubblicaRaw(coppia.publicKey), sealedPriv, parti: [a, b, c] };
}

export async function apriRecupero(
  orgId: string,
  R: Uint8Array,
  pubKey: Uint8Array,
  sealedPriv: Uint8Array
): Promise<CryptoKeyPair> {
  const pkcs8 = await unseal(await kekRecupero(R), sealedPriv, aad('recovery', orgId));
  return coppiaDaPkcs8(ab(pkcs8), pubKey);
}

export async function ricomponi(parti: Uint8Array[]): Promise<Uint8Array> {
  if (parti.length < 2) throw new ErroreRiservata('parti', 'servono almeno due parti');
  const x = new Set(parti.map(p => p[p.length - 1]));
  if (x.size !== parti.length)
    throw new ErroreRiservata('parti', 'due parti uguali: ne serve una diversa');
  const R = await combine(parti);
  if (R.length !== 32) throw new ErroreRiservata('parti', 'parti di lunghezza inattesa');
  return R;
}

// ── custodia DCAM (protocollo §5.2): l'info HPKE è AAD("custodia", orgId), niente epoca ──
export async function chiudiPerCustodia(
  parteB: Uint8Array,
  orgId: string,
  pubCustodia: Uint8Array = CUSTODIA_PUBBLICA
): Promise<Uint8Array> {
  const { ct, enc } = await suite.seal(
    { recipientPublicKey: await importaPubblica(pubCustodia), info: ab(aad('custodia', orgId)) },
    ab(parteB)
  );
  return concatena(new Uint8Array(enc), new Uint8Array(ct));
}

export async function apriPerCustodia(
  chiusa: Uint8Array,
  orgId: string,
  coppia: CryptoKeyPair
): Promise<Uint8Array> {
  const pt = await suite.open(
    { recipientKey: coppia, enc: ab(chiusa.subarray(0, ENC)), info: ab(aad('custodia', orgId)) },
    ab(chiusa.subarray(ENC))
  );
  return new Uint8Array(pt);
}

// ── trasferimento (protocollo §4.3) ───────────────────────────────────
export type PacchettoTrasferimento = {
  orgId: string;
  forUserId: string;
  epochs: Record<string, string>; // epoca → E_n in base64url
  manifest: { epoch: number; seq: number; blob: string };
};

export function nuovoCodiceTrasferimento(): string {
  return simboliCasuali(20);
}

async function chiaveTrasferimento(codice: string, transferId: string): Promise<CryptoKey> {
  const norm = normalizza(codice);
  if (norm.length !== 20) throw new ErroreRiservata('apertura', 'il codice ha 20 caratteri');
  return hkdfAes(
    new TextEncoder().encode(norm),
    'dcam.riservata.v1.transfer',
    new TextEncoder().encode(transferId)
  );
}

export async function chiudiTrasferimento(
  codice: string,
  transferId: string,
  orgId: string,
  forUserId: string,
  p: PacchettoTrasferimento
): Promise<Uint8Array> {
  const k = await chiaveTrasferimento(codice, transferId);
  return seal(
    k,
    new TextEncoder().encode(JSON.stringify(p)),
    aad('transfer', orgId, transferId, forUserId)
  );
}

export async function apriTrasferimento(
  codice: string,
  transferId: string,
  orgId: string,
  forUserId: string,
  busta: Uint8Array
): Promise<PacchettoTrasferimento> {
  const k = await chiaveTrasferimento(codice, transferId);
  const pt = await unseal(k, busta, aad('transfer', orgId, transferId, forUserId));
  const p = JSON.parse(new TextDecoder().decode(pt)) as PacchettoTrasferimento;
  if (p.orgId !== orgId || p.forUserId !== forUserId) {
    throw new ErroreRiservata('apertura', 'pacchetto destinato ad altri');
  }
  return p;
}
