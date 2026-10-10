// @vitest-environment node
// src/oggetto.test.ts
import { describe, expect, test } from 'vitest';
import { createDecipheriv, hkdfSync } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { chiudiParte, apriParte, epocaDi, chiudiJson, apriJson } from './oggetto';
import { generaChiaveEpoca } from './chiavi';
import { aad, TETTO_DECOMPRESSO } from './formato';

const ind = { orgId: 'org1', kind: 'part', objectId: 'p1', rev: 3 };

describe('busta DCR2 di una parte (protocollo §3.2)', () => {
  test('Node crypto la apre agli offset della specifica, con DK = HKDF(E, "…data")', async () => {
    const E = generaChiaveEpoca();
    const busta = await chiudiParte(
      E,
      7,
      ind,
      'body',
      new TextEncoder().encode('<svg/>'.repeat(100))
    );
    expect(Buffer.from(busta.subarray(0, 4)).toString()).toBe('DCR2');
    expect(busta[4]).toBe(1);
    expect(Buffer.from(busta).readUInt32BE(5)).toBe(7);
    const dk = Buffer.from(hkdfSync('sha256', E, Buffer.alloc(0), 'dcam.riservata.v2.data', 32));
    const d = createDecipheriv('aes-256-gcm', dk, busta.subarray(9, 21));
    d.setAAD(aad('obj', 'org1', 'part', 'p1', 3, 'body', 7));
    d.setAuthTag(busta.subarray(busta.length - 16));
    const pt = Buffer.concat([d.update(busta.subarray(21, busta.length - 16)), d.final()]);
    expect(pt[0]).toBe(1); // codec deflate per body
    expect(inflateSync(pt.subarray(1)).toString()).toBe('<svg/>'.repeat(100));
  });

  test('meta e thumb non compressi (codec 0)', async () => {
    const E = generaChiaveEpoca();
    const b = await chiudiParte(E, 1, ind, 'meta', new Uint8Array([1, 2]));
    expect(await apriParte(() => E, ind, 'meta', b)).toEqual(new Uint8Array([1, 2]));
  });

  test.each([
    ['altro oggetto', { ...ind, objectId: 'p2' }, 'body'],
    ['altra revisione (rollback mascherato)', { ...ind, rev: 2 }, 'body'],
    ['altro tipo', { ...ind, kind: 'nesting' }, 'body'],
    ['altra azienda', { ...ind, orgId: 'org2' }, 'body'],
    ['altra parte', ind, 'meta'],
  ] as const)('busta spostata dal server: %s → errore', async (_n, altro, parte) => {
    const E = generaChiaveEpoca();
    const b = await chiudiParte(E, 1, ind, 'body', new Uint8Array([5]));
    await expect(apriParte(() => E, altro, parte, b)).rejects.toMatchObject({ codice: 'apertura' });
  });

  test("epoca dichiarata nell'intestazione falsificata → errore (l'epoca è anche nell'AAD)", async () => {
    const E1 = generaChiaveEpoca();
    const b = await chiudiParte(E1, 1, ind, 'body', new Uint8Array([5]));
    const f = b.slice();
    f[8] = 2;
    await expect(
      apriParte(e => (e === 1 || e === 2 ? E1 : undefined), ind, 'body', f)
    ).rejects.toMatchObject({ codice: 'apertura' });
  });

  test('epoca di cui non ho la chiave → «epoca»', async () => {
    const b = await chiudiParte(generaChiaveEpoca(), 5, ind, 'body', new Uint8Array([5]));
    expect(epocaDi(b)).toBe(5);
    await expect(apriParte(() => undefined, ind, 'body', b)).rejects.toMatchObject({
      codice: 'epoca',
    });
  });

  test('JSON: ritorno esatto', async () => {
    const E = generaChiaveEpoca();
    const meta = { name: 'FLANGIA-CANARINO', thickness: 3, customFields: { 1: 'x' } };
    const b = await chiudiJson(E, 1, ind, 'meta', meta);
    expect(await apriJson(() => E, ind, 'meta', b)).toEqual(meta);
  });
});

describe('bomba di decompressione (protocollo §3.2)', () => {
  test('oltre il tetto → formato; al tetto esatto passa', async () => {
    const E = generaChiaveEpoca();
    const b = await chiudiParte(E, 1, ind, 'body', new Uint8Array(1_000_000));
    await expect(apriParte(() => E, ind, 'body', b, 999_999)).rejects.toMatchObject({
      codice: 'formato',
    });
    expect((await apriParte(() => E, ind, 'body', b, 1_000_000)).length).toBe(1_000_000);
  });
  test('tetto di fabbrica 256 MiB: 257 MiB di zeri (busta di pochi KB) si fermano', async () => {
    expect(TETTO_DECOMPRESSO).toBe(256 * 1024 * 1024);
    const E = generaChiaveEpoca();
    const b = await chiudiParte(E, 1, ind, 'body', new Uint8Array(257 * 1024 * 1024));
    expect(b.length).toBeLessThan(1024 * 1024);
    await expect(apriParte(() => E, ind, 'body', b)).rejects.toMatchObject({ codice: 'formato' });
  }, 60_000);
});
