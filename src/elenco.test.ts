// @vitest-environment node
// src/elenco.test.ts
import { describe, expect, test } from 'vitest';
import {
  chiudiElenco,
  apriElenco,
  conAggiunti,
  perRinnovo,
  chiusurePerEpoca,
  type Elenco,
} from './elenco';
import { generaChiaveEpoca, generaCoppia, pubblicaRaw, apriPer } from './chiavi';
import { a64 } from './bytes';

async function elencoDiProva(): Promise<{ el: Elenco; coppie: Record<string, CryptoKeyPair> }> {
  const coppie: Record<string, CryptoKeyPair> = {
    u1: await generaCoppia(false),
    d1: await generaCoppia(false),
    u2: await generaCoppia(false),
    d2: await generaCoppia(false),
    rec: await generaCoppia(false),
  };
  const pk = async (n: string) => a64(await pubblicaRaw(coppie[n].publicKey));
  return {
    coppie,
    el: {
      v: 1,
      orgId: 'org1',
      epoch: 1,
      seq: 1,
      recovery: { pubKey: await pk('rec') },
      recipients: [
        {
          kind: 'person',
          id: 'u1',
          userId: 'u1',
          pubKey: await pk('u1'),
          addedBy: 'u1',
          addedAt: 1,
        },
        {
          kind: 'device',
          id: 'd1',
          userId: 'u1',
          label: 'Ufficio',
          pubKey: await pk('d1'),
          addedBy: 'u1',
          addedAt: 1,
        },
        {
          kind: 'person',
          id: 'u2',
          userId: 'u2',
          pubKey: await pk('u2'),
          addedBy: 'u1',
          addedAt: 2,
        },
        {
          kind: 'device',
          id: 'd2',
          userId: 'u2',
          label: 'Officina',
          pubKey: await pk('d2'),
          addedBy: 'u2',
          addedAt: 2,
        },
      ],
    },
  };
}

describe('elenco dei destinatari (protocollo §3.5)', () => {
  test('chiudi/apri con i valori attesi', async () => {
    const E = generaChiaveEpoca();
    const { el } = await elencoDiProva();
    const b = await chiudiElenco(E, el);
    expect(await apriElenco(E, b, { orgId: 'org1', epoch: 1, seq: 1 })).toEqual(el);
  });
  test('il server consegna un elenco vecchio come nuovo (seq diverso) → «elenco»', async () => {
    const E = generaChiaveEpoca();
    const { el } = await elencoDiProva();
    const b = await chiudiElenco(E, el);
    await expect(apriElenco(E, b, { orgId: 'org1', epoch: 1, seq: 2 })).rejects.toMatchObject({
      codice: 'apertura',
    });
  });
  test('conAggiunti: seq+1, niente doppioni per (kind,id)', async () => {
    const { el } = await elencoDiProva();
    const n = conAggiunti(el, [el.recipients[1]]);
    expect(n.seq).toBe(2);
    expect(n.recipients).toHaveLength(4);
  });
  test('perRinnovo senza u2: via la persona E tutte le sue postazioni; epoca+1, seq 1', async () => {
    const { el } = await elencoDiProva();
    const n = perRinnovo(el, { userId: 'u2' });
    expect(n.epoch).toBe(2);
    expect(n.seq).toBe(1);
    expect(n.recipients.map(r => r.id).sort()).toEqual(['d1', 'u1']);
  });
  test('perRinnovo senza la postazione d1: resta la persona u1', async () => {
    const { el } = await elencoDiProva();
    expect(
      perRinnovo(el, { deviceId: 'd1' })
        .recipients.map(r => r.id)
        .sort()
    ).toEqual(['d2', 'u1', 'u2']);
  });
  test('chiusurePerEpoca: una per destinatario + recupero; chi è fuori NON apre', async () => {
    const { el, coppie } = await elencoDiProva();
    const n = perRinnovo(el, { userId: 'u2' });
    const E2 = generaChiaveEpoca();
    const w = await chiusurePerEpoca(E2, n);
    expect(w.map(x => `${x.kind}:${x.id}`).sort()).toEqual([
      'device:d1',
      'person:u1',
      'recovery:recovery',
    ]);
    const perD1 = w.find(x => x.id === 'd1')!;
    expect(
      await apriPer(perD1.wrapped, coppie.d1, { orgId: 'org1', epoch: 2, kind: 'device', id: 'd1' })
    ).toEqual(E2);
    await expect(
      apriPer(perD1.wrapped, coppie.d2, { orgId: 'org1', epoch: 2, kind: 'device', id: 'd1' })
    ).rejects.toBeDefined();
  });
});
