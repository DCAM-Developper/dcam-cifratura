// Vettori fissi del protocollo v1: buste prodotte dalla 0.1.0 con chiavi note (vettori/genera.mjs).
// Girano in Node e in Chromium: ogni ambiente deve aprire esattamente le stesse buste.
import { describe, expect, test } from 'vitest';
import v from './v1.json';
import {
  aad, apriJson, apriParte, epocaDi, apriElenco, apriPer, apriPersona, ricomponi,
  apriRecupero, apriPerCustodia, apriTrasferimento, importaPubblica, CURVA, da64, ErroreRiservata,
  type Elenco, type ContestoChiusura,
} from '../src/index';

const h = (s: string) => Uint8Array.from(s.match(/../g)!.map(b => parseInt(b, 16)));
const toHex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const E = h(v.chiaveEpoca);
const chiavePer = (e: number) => (e === v.epoca ? E : undefined);
async function coppia(): Promise<CryptoKeyPair> {
  const privateKey = await crypto.subtle.importKey('pkcs8', h(v.destinatario.pkcs8), CURVA, false, ['deriveBits']);
  return { privateKey, publicKey: await importaPubblica(h(v.destinatario.pub)) };
}
const alterata = (hex: string) => {
  const b = h(hex);
  b[b.length - 1] ^= 1;
  return b;
};

describe('vettori v1', () => {
  test('AAD', () => {
    expect(toHex(aad(...(v.aad.campi as Array<string | number>)))).toBe(v.aad.hex);
  });

  test('DCR1 meta (codec 0) ed epoca in chiaro', async () => {
    const b = h(v.DCR1_meta.busta);
    expect(new TextDecoder().decode(b.subarray(0, 4))).toBe('DCR1');
    expect(epocaDi(b)).toBe(v.epoca);
    expect(await apriJson(chiavePer, v.indirizzo, 'meta', b)).toEqual(v.DCR1_meta.json);
  });

  test('DCR1 body (codec 1, deflate)', async () => {
    const pt = await apriParte(chiavePer, v.indirizzo, 'body', h(v.DCR1_body.busta));
    expect(new TextDecoder().decode(pt)).toBe(v.DCR1_body.testo);
  });

  test('DCR1: indirizzo diverso o busta alterata non si aprono', async () => {
    await expect(apriParte(chiavePer, { ...v.indirizzo, rev: 4 }, 'body', h(v.DCR1_body.busta))).rejects.toMatchObject({ codice: 'apertura' });
    await expect(apriParte(chiavePer, v.indirizzo, 'meta', h(v.DCR1_body.busta))).rejects.toMatchObject({ codice: 'apertura' });
    await expect(apriParte(chiavePer, v.indirizzo, 'body', alterata(v.DCR1_body.busta))).rejects.toBeInstanceOf(ErroreRiservata);
  });

  test('DCM1 elenco', async () => {
    const el = v.DCM1.elenco as Elenco;
    const atteso = { orgId: el.orgId, epoch: el.epoch, seq: el.seq };
    expect(await apriElenco(E, h(v.DCM1.busta), atteso)).toEqual(el);
    await expect(apriElenco(E, h(v.DCM1.busta), { ...atteso, seq: 1 })).rejects.toMatchObject({ codice: 'apertura' });
  });

  test('chiusura HPKE della chiave d\'epoca', async () => {
    const c = v.chiusura.contesto as ContestoChiusura;
    expect(toHex(await apriPer(h(v.chiusura.chiusa), await coppia(), c))).toBe(v.chiaveEpoca);
    await expect(apriPer(h(v.chiusura.chiusa), await coppia(), { ...c, epoch: c.epoch + 1 })).rejects.toMatchObject({ codice: 'apertura' });
  });

  test('DCS1 persona: frase giusta apre, frase sbagliata no', async () => {
    const p = v.DCS1_persona;
    const k = await apriPersona(p.orgId, p.userId, p.frase, p.record as never);
    expect(toHex(new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey)))).toBe(toHex(da64(p.record.pubKey)));
    await expect(apriPersona(p.orgId, p.userId, p.frase + 'x', p.record as never)).rejects.toMatchObject({ codice: 'frase' });
  });

  test('recupero: due parti qualsiasi su tre ricompongono R, R apre la privata', async () => {
    const r = v.recupero;
    for (const [a, b] of [[0, 1], [0, 2], [1, 2]]) {
      expect(toHex(await ricomponi([h(r.parti[a]), h(r.parti[b])]))).toBe(r.R);
    }
    const k = await apriRecupero(r.orgId, h(r.R), h(r.pub), h(r.sealedPriv));
    expect(toHex(new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey)))).toBe(r.pub);
  });

  test('custodia: parte B chiusa per la chiave di custodia (qui quella di prova)', async () => {
    const c = v.custodia;
    expect(toHex(await apriPerCustodia(h(c.chiusa), c.orgId, await coppia()))).toBe(c.parteB);
  });

  test('DCS1 trasferimento', async () => {
    const t = v.DCS1_trasferimento;
    expect(await apriTrasferimento(t.codice, t.transferId, t.orgId, t.forUserId, h(t.busta))).toEqual(t.pacchetto);
    await expect(apriTrasferimento(t.codice, 't-2', t.orgId, t.forUserId, h(t.busta))).rejects.toMatchObject({ codice: 'apertura' });
  });
});
