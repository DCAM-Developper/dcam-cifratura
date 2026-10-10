// @vitest-environment node
// src/chiavi.test.ts
import { describe, expect, test } from 'vitest';
import {
  generaChiaveEpoca,
  generaCoppia,
  pubblicaRaw,
  chiudiPer,
  apriPer,
  creaPersona,
  apriPersona,
  creaRecupero,
  apriRecupero,
  ricomponi,
  nuovoCodiceTrasferimento,
  chiudiTrasferimento,
  apriTrasferimento,
  chiudiPerCustodia,
  apriPerCustodia,
  chiaveDaFrase,
  TETTI_KDF,
  PARAMETRI_KDF,
  type ParametriKdf,
} from './chiavi';
import { a64 } from './bytes';

// Parametri bassi SOLO per la velocità dei test; un test dedicato usa quelli veri.
const KDF_TEST: ParametriKdf = {
  alg: 'argon2id13',
  ops: 1,
  mem: 8 * 1024 * 1024,
  salt: 'AAAAAAAAAAAAAAAAAAAAAA',
};

describe("chiusura di una chiave d'epoca per un destinatario (HPKE)", () => {
  const ctx = { orgId: 'org1', epoch: 1, kind: 'device' as const, id: 'dev1' };

  test('si apre solo con la coppia giusta e il contesto giusto', async () => {
    const e = generaChiaveEpoca();
    const dest = await generaCoppia(false);
    const altra = await generaCoppia(false);
    const w = await chiudiPer(e, await pubblicaRaw(dest.publicKey), ctx);
    expect(w).toHaveLength(113); // enc P-256 non compresso (65) + chiave cifrata (48)
    expect(await apriPer(w, dest, ctx)).toEqual(e);
    await expect(apriPer(w, altra, ctx)).rejects.toMatchObject({ codice: 'apertura' });
  });

  test.each([
    ['epoca', { ...ctx, epoch: 2 }],
    ['destinatario', { ...ctx, id: 'dev2' }],
    ['tipo', { ...ctx, kind: 'person' as const }],
    ['azienda', { ...ctx, orgId: 'org2' }],
  ])("il server non può spacciarla per un'altra (%s)", async (_n, altroCtx) => {
    const e = generaChiaveEpoca();
    const dest = await generaCoppia(false);
    const w = await chiudiPer(e, await pubblicaRaw(dest.publicKey), ctx);
    await expect(apriPer(w, dest, altroCtx)).rejects.toMatchObject({ codice: 'apertura' });
  });
});

describe('persona: privata chiusa con la frase', () => {
  test('la frase giusta apre, una sbagliata dà «frase»', async () => {
    const { record, coppia } = await creaPersona(
      'org1',
      'u1',
      'cavallo batteria graffetta',
      KDF_TEST
    );
    const riaperta = await apriPersona('org1', 'u1', 'cavallo batteria graffetta', record);
    const e = generaChiaveEpoca();
    const ctx = { orgId: 'org1', epoch: 1, kind: 'person' as const, id: 'u1' };
    const w = await chiudiPer(e, await pubblicaRaw(coppia.publicKey), ctx);
    expect(await apriPer(w, riaperta, ctx)).toEqual(e);
    await expect(
      apriPersona('org1', 'u1', 'cavallo batteria graffett', record)
    ).rejects.toMatchObject({ codice: 'frase' });
  });
  test('il record di u1 non si apre come record di u2 (scambio di righe sul server)', async () => {
    const { record } = await creaPersona('org1', 'u1', 'frase lunga a sufficienza', KDF_TEST);
    await expect(
      apriPersona('org1', 'u2', 'frase lunga a sufficienza', record)
    ).rejects.toMatchObject({ codice: 'frase' });
  });
  test('il record lega pubblica e parametri KDF: il server non li cambia', async () => {
    const { record } = await creaPersona('org1', 'u1', 'frase lunga a sufficienza', KDF_TEST);
    const altraPub = a64(await pubblicaRaw((await generaCoppia(true)).publicKey));
    for (const r of [
      { ...record, pubKey: altraPub },
      { ...record, kdf: { ...record.kdf, ops: 2 } },
      { ...record, kdf: { ...record.kdf, mem: 9 * 1024 * 1024 } },
      { ...record, kdf: { ...record.kdf, salt: 'AQAAAAAAAAAAAAAAAAAAAA' } },
    ]) {
      await expect(apriPersona('org1', 'u1', 'frase lunga a sufficienza', r)).rejects.toMatchObject(
        { codice: 'frase' }
      );
    }
  });
  test('tetti KDF: il valore di fabbrica sta dentro; mem enorme, ops enorme, sale corto → formato', async () => {
    expect(PARAMETRI_KDF.mem).toBeGreaterThanOrEqual(TETTI_KDF.mem[0]);
    expect(PARAMETRI_KDF.mem).toBeLessThanOrEqual(TETTI_KDF.mem[1]);
    expect(PARAMETRI_KDF.ops).toBeLessThanOrEqual(TETTI_KDF.ops[1]);
    for (const p of [
      { ...KDF_TEST, mem: 256 * 1024 * 1024 + 1 },
      { ...KDF_TEST, mem: 4 * 1024 * 1024 * 1024 },
      { ...KDF_TEST, mem: 8 * 1024 * 1024 - 1 },
      { ...KDF_TEST, ops: 11 },
      { ...KDF_TEST, ops: 0 },
      { ...KDF_TEST, ops: 1.5 },
      { ...KDF_TEST, salt: 'AAAA' },
      { ...KDF_TEST, alg: 'scrypt' as 'argon2id13' },
    ]) {
      await expect(chiaveDaFrase('frase lunga a sufficienza', p)).rejects.toMatchObject({
        codice: 'formato',
      });
    }
  });
  test('frase sotto i 12 caratteri rifiutata alla creazione', async () => {
    await expect(creaPersona('org1', 'u1', 'corta', KDF_TEST)).rejects.toMatchObject({
      codice: 'frase',
    });
  });
  test('NFC: la stessa frase scritta con accenti composti o scomposti apre', async () => {
    const { record } = await creaPersona('org1', 'u1', 'perché sì, è così', KDF_TEST);
    await expect(apriPersona('org1', 'u1', 'perché sì, è così', record)).resolves.toBeDefined();
  });
  test('parametri di produzione (lento, una volta)', async () => {
    const { record } = await creaPersona('org1', 'u1', 'frase di produzione lunga');
    expect(record.kdf.ops).toBe(3);
    expect(record.kdf.mem).toBe(64 * 1024 * 1024);
  }, 30_000);
});

const ANCORA = Uint8Array.from({ length: 32 }, (_, i) => i);

describe('recupero', () => {
  test('R apre la privata di recupero; due parti qualsiasi ricompongono R', async () => {
    const rec = await creaRecupero('org1', ANCORA);
    const { coppia, ancora } = await apriRecupero('org1', rec.R, rec.pubKey, rec.sealedPriv);
    expect(ancora).toEqual(ANCORA);
    const e = generaChiaveEpoca();
    const ctx = { orgId: 'org1', epoch: 3, kind: 'recovery' as const, id: 'recovery' };
    const w = await chiudiPer(e, rec.pubKey, ctx);
    expect(await apriPer(w, coppia, ctx)).toEqual(e);
    const [a, b, c] = rec.parti;
    for (const due of [
      [a, b],
      [b, c],
      [c, a],
    ])
      expect(await ricomponi(due)).toEqual(rec.R);
  });
  test('una parte sola → «parti»; la stessa parte due volte → «parti»', async () => {
    const rec = await creaRecupero('org1', ANCORA);
    await expect(ricomponi([rec.parti[0]])).rejects.toMatchObject({ codice: 'parti' });
    await expect(ricomponi([rec.parti[0], rec.parti[0]])).rejects.toMatchObject({
      codice: 'parti',
    });
  });
  test("la privata di recupero è legata alla sua pubblica: un'altra pubblica non apre", async () => {
    const rec = await creaRecupero('org1', ANCORA);
    const altra = await pubblicaRaw((await generaCoppia(true)).publicKey);
    await expect(apriRecupero('org1', rec.R, altra, rec.sealedPriv)).rejects.toMatchObject({
      codice: 'apertura',
    });
    await expect(creaRecupero('org1', new Uint8Array(31))).rejects.toMatchObject({
      codice: 'formato',
    });
  });
  test('parti di due aziende diverse ricompongono un R che NON apre (errore, non dati)', async () => {
    const r1 = await creaRecupero('org1', ANCORA);
    const r2 = await creaRecupero('org1', ANCORA);
    const sbagliato = await ricomponi([r1.parti[0], r2.parti[1]]);
    await expect(apriRecupero('org1', sbagliato, r1.pubKey, r1.sealedPriv)).rejects.toMatchObject({
      codice: 'apertura',
    });
  });
});

describe('trasferimento (postazione nuova, livelli 1-2)', () => {
  test('codice di 20 simboli; il pacchetto si apre solo col codice giusto e il destinatario giusto', async () => {
    const codice = nuovoCodiceTrasferimento();
    expect(codice).toMatch(/^[0-9A-HJKMNP-TV-Z]{20}$/);
    const pacchetto = {
      orgId: 'org1',
      forUserId: 'u9',
      epochs: { '1': 'AAA' },
      manifest: { epoch: 1, seq: 2, blob: 'BBB' },
    };
    const b = await chiudiTrasferimento(codice, 't1', 'org1', 'u9', pacchetto);
    expect(await apriTrasferimento(codice.toLowerCase(), 't1', 'org1', 'u9', b)).toEqual(pacchetto);
    const sbagliato = (codice[0] === '0' ? '1' : '0') + codice.slice(1);
    await expect(apriTrasferimento(sbagliato, 't1', 'org1', 'u9', b)).rejects.toMatchObject({
      codice: 'apertura',
    });
    await expect(apriTrasferimento(codice, 't1', 'org1', 'u8', b)).rejects.toMatchObject({
      codice: 'apertura',
    });
  });
});

describe('custodia DCAM', () => {
  test('la parte B chiusa per la custodia si apre con la privata di custodia, solo per il SUO kit', async () => {
    const cust = await generaCoppia(true);
    const pub = await pubblicaRaw(cust.publicKey);
    const pubRP = await pubblicaRaw((await generaCoppia(true)).publicKey);
    const altroRP = await pubblicaRaw((await generaCoppia(true)).publicKey);
    const B = crypto.getRandomValues(new Uint8Array(33));
    const chiusa = await chiudiPerCustodia(B, 'org1', pubRP, pub);
    expect(chiusa.length).toBe(114);
    expect(await apriPerCustodia(chiusa, 'org1', pubRP, cust)).toEqual(B);
    await expect(apriPerCustodia(chiusa, 'org1', altroRP, cust)).rejects.toMatchObject({
      codice: 'apertura',
    });
    await expect(apriPerCustodia(chiusa, 'org2', pubRP, cust)).rejects.toMatchObject({
      codice: 'apertura',
    });
    await expect(
      apriPerCustodia(chiusa.subarray(0, 113), 'org1', pubRP, cust)
    ).rejects.toMatchObject({ codice: 'formato' });
  });
});
