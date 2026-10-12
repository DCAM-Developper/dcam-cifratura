// Vettori fissi del protocollo v2: buste prodotte dalla 0.2.0 con chiavi note (vettori/genera.mjs).
// Girano in Node e in Chromium: ogni ambiente deve aprire esattamente le stesse buste.
import { describe, expect, test } from 'vitest';
import v from './v2.json';
import {
  aad, apriJson, apriParte, epocaDi, apriElenco, apriPer, apriPersona, ricomponi,
  apriRecupero, apriPerCustodia, apriTrasferimento, importaPubblica, CURVA, da64, ErroreRiservata,
  impegno, verificaTransizione,
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

describe('vettori v2', () => {
  test('AAD', () => {
    expect(toHex(aad(...(v.aad.campi as Array<string | number>)))).toBe(v.aad.hex);
  });

  test('DCR2 meta (codec 0) ed epoca in chiaro', async () => {
    const b = h(v.DCR2_meta.busta);
    expect(new TextDecoder().decode(b.subarray(0, 4))).toBe('DCR2');
    expect(epocaDi(b)).toBe(v.epoca);
    expect(await apriJson(chiavePer, v.indirizzo, 'meta', b)).toEqual(v.DCR2_meta.json);
  });

  test('DCR2 body (codec 1, deflate)', async () => {
    const pt = await apriParte(chiavePer, v.indirizzo, 'body', h(v.DCR2_body.busta));
    expect(new TextDecoder().decode(pt)).toBe(v.DCR2_body.testo);
  });

  test('DCR2: indirizzo diverso o busta alterata non si aprono', async () => {
    await expect(apriParte(chiavePer, { ...v.indirizzo, rev: 4 }, 'body', h(v.DCR2_body.busta))).rejects.toMatchObject({ codice: 'apertura' });
    await expect(apriParte(chiavePer, v.indirizzo, 'meta', h(v.DCR2_body.busta))).rejects.toMatchObject({ codice: 'apertura' });
    await expect(apriParte(chiavePer, v.indirizzo, 'body', alterata(v.DCR2_body.busta))).rejects.toBeInstanceOf(ErroreRiservata);
  });

  test('DCM2 elenco', async () => {
    const el = v.DCM2.elenco as Elenco;
    const atteso = { orgId: el.orgId, epoch: el.epoch, seq: el.seq };
    expect(await apriElenco(E, h(v.DCM2.busta), atteso)).toEqual(el);
    await expect(apriElenco(E, h(v.DCM2.busta), { ...atteso, seq: 1 })).rejects.toMatchObject({ codice: 'apertura' });
  });

  test('chiusura HPKE della chiave d\'epoca', async () => {
    const c = v.chiusura.contesto as ContestoChiusura;
    expect(toHex(await apriPer(h(v.chiusura.chiusa), await coppia(), c))).toBe(v.chiaveEpoca);
    await expect(apriPer(h(v.chiusura.chiusa), await coppia(), { ...c, epoch: c.epoch + 1 })).rejects.toMatchObject({ codice: 'apertura' });
  });

  test('DCS2 persona: frase giusta apre, frase sbagliata no', async () => {
    const p = v.DCS2_persona;
    const k = await apriPersona(p.orgId, p.userId, p.frase, p.record as never);
    expect(toHex(new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey)))).toBe(toHex(da64(p.record.pubKey)));
    await expect(apriPersona(p.orgId, p.userId, p.frase + 'x', p.record as never)).rejects.toMatchObject({ codice: 'frase' });
  });

  test('recupero: due parti qualsiasi su tre ricompongono R, R apre la privata', async () => {
    const r = v.recupero;
    for (const [a, b] of [[0, 1], [0, 2], [1, 2]]) {
      expect(toHex(await ricomponi([h(r.parti[a]), h(r.parti[b])]))).toBe(r.R);
    }
    const { coppia: k, ancora } = await apriRecupero(r.orgId, h(r.R), h(r.pub), h(r.sealedPriv));
    expect(toHex(new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey)))).toBe(r.pub);
    expect(toHex(ancora)).toBe(r.ancora);
  });

  test('custodia: parte B chiusa per la chiave di custodia (qui quella di prova)', async () => {
    const c = v.custodia;
    expect(toHex(await apriPerCustodia(h(c.chiusa), c.orgId, h(v.recupero.pub), await coppia()))).toBe(c.parteB);
  });

  test('DCS2 trasferimento', async () => {
    const t = v.DCS2_trasferimento;
    expect(await apriTrasferimento(t.codice, t.transferId, t.orgId, t.forUserId, h(t.busta))).toEqual(t.pacchetto);
    await expect(apriTrasferimento(t.codice, 't-2', t.orgId, t.forUserId, h(t.busta))).rejects.toMatchObject({ codice: 'apertura' });
  });

  test('impegno della chiave d\'epoca', async () => {
    expect(toHex(await impegno(h(v.impegno.chiave)))).toBe(v.impegno.impegno);
  });

  test('transizione firmata: si verifica; con un\'altra chiave nuova no', async () => {
    const t = v.transizione;
    const tr = { epoch: t.epoch, prevSeq: t.prevSeq, prevBlob: h(v.DCM2.busta), signerId: t.signerId, sig: h(t.sig) };
    await expect(verificaTransizione(v.indirizzo.orgId, E, h(t.chiaveNuova), tr)).resolves.toBe(v.DCM2.elenco.recipients[0].signKey);
    await expect(verificaTransizione(v.indirizzo.orgId, E, E, tr)).rejects.toMatchObject({ codice: 'firma' });
  });
});
