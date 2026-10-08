// src/oggetto.ts
// Parti di una versione — protocollo §3.2.
import {
  aad,
  cifraAes,
  decifraAes,
  scriviBusta,
  leggiBusta,
  comprimi,
  decomprimi,
} from './formato';
import { chiaveDati } from './chiavi';
import { concatena } from './bytes';
import { ErroreRiservata } from './errori';

export type Parte = 'meta' | 'thumb' | 'body';
export type Indirizzo = { orgId: string; kind: string; objectId: string; rev: number };
const ALG_AES256GCM = 1;
const aadParte = (i: Indirizzo, p: Parte, epoch: number) =>
  aad('obj', i.orgId, i.kind, i.objectId, i.rev, p, epoch);

export async function chiudiParte(
  E: Uint8Array,
  epoch: number,
  ind: Indirizzo,
  parte: Parte,
  dati: Uint8Array
): Promise<Uint8Array> {
  const codec = parte === 'body' ? 1 : 0;
  const pt = concatena(new Uint8Array([codec]), codec ? await comprimi(dati) : dati);
  const { nonce, cifrato } = await cifraAes(await chiaveDati(E), pt, aadParte(ind, parte, epoch));
  const intest = new Uint8Array(5);
  intest[0] = ALG_AES256GCM;
  new DataView(intest.buffer).setUint32(1, epoch);
  return scriviBusta('DCR1', intest, nonce, cifrato);
}

export function epocaDi(busta: Uint8Array): number {
  const { intestazione } = leggiBusta('DCR1', busta, 5);
  if (intestazione[0] !== ALG_AES256GCM)
    throw new ErroreRiservata('formato', `algoritmo ${intestazione[0]} sconosciuto`);
  return new DataView(intestazione.buffer, intestazione.byteOffset, 5).getUint32(1);
}

export async function apriParte(
  chiavePer: (epoch: number) => Uint8Array | undefined,
  ind: Indirizzo,
  parte: Parte,
  busta: Uint8Array
): Promise<Uint8Array> {
  const epoch = epocaDi(busta);
  const E = chiavePer(epoch);
  if (!E) throw new ErroreRiservata('epoca', `manca la chiave dell'epoca ${epoch}`);
  const { nonce, cifrato } = leggiBusta('DCR1', busta, 5);
  const pt = await decifraAes(await chiaveDati(E), nonce, cifrato, aadParte(ind, parte, epoch));
  if (pt[0] === 0) return pt.subarray(1);
  if (pt[0] === 1) return decomprimi(pt.subarray(1));
  throw new ErroreRiservata('formato', `codec ${pt[0]} sconosciuto`);
}

export const chiudiJson = (
  E: Uint8Array,
  epoch: number,
  ind: Indirizzo,
  parte: Parte,
  v: unknown
) => chiudiParte(E, epoch, ind, parte, new TextEncoder().encode(JSON.stringify(v)));

export async function apriJson<T>(
  chiavePer: (e: number) => Uint8Array | undefined,
  ind: Indirizzo,
  parte: Parte,
  b: Uint8Array
): Promise<T> {
  return JSON.parse(new TextDecoder().decode(await apriParte(chiavePer, ind, parte, b))) as T;
}
