// Epoche firmate (protocollo §3.6, §4.5): la forgia del server rifiutata, l'epoca legittima accettata.
import { describe, expect, test } from 'vitest';
import { generaChiaveEpoca, generaCoppia, pubblicaRaw, chiudiPer, apriPer } from './chiavi';
import { chiudiElenco, perRinnovo, type Elenco } from './elenco';
import {
  generaCoppiaFirma,
  impegno,
  firmaTransizione,
  verificaTransizione,
  verificaChiavi,
  type Transizione,
} from './firma';
import { a64 } from './bytes';
import { ErroreRiservata } from './errori';

const orgId = 'org1';

/** Un'azienda all'epoca 1: una postazione d1 con la sua coppia di firma, elenco seq 1. */
async function azienda() {
  const E1 = generaChiaveEpoca();
  const dev = await generaCoppia(false);
  const firma = await generaCoppiaFirma(false);
  const rec = await generaCoppia(true);
  const el1: Elenco = {
    v: 2,
    orgId,
    epoch: 1,
    seq: 1,
    recovery: { pubKey: a64(await pubblicaRaw(rec.publicKey)) },
    recipients: [
      {
        kind: 'device',
        id: 'd1',
        userId: 'u1',
        pubKey: a64(await pubblicaRaw(dev.publicKey)),
        signKey: a64(await pubblicaRaw(firma.publicKey)),
        addedBy: 'u1',
        addedAt: 1,
      },
    ],
  };
  const blob1 = await chiudiElenco(E1, el1);
  return { E1, dev, firma, el1, blob1 };
}

const codice = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    return e instanceof ErroreRiservata ? e.codice : `altro: ${String(e)}`;
  }
  return 'accettata';
};

describe('epoche firmate', () => {
  test('impegno: 32 byte, deterministico, diverso per chiavi diverse', async () => {
    const E = generaChiaveEpoca();
    expect((await impegno(E)).length).toBe(32);
    expect(await impegno(E)).toEqual(await impegno(E.slice()));
    expect(await impegno(E)).not.toEqual(await impegno(generaChiaveEpoca()));
  });

  test('rinnovo legittimo: firmato da una postazione dell’elenco precedente → accettato', async () => {
    const a = await azienda();
    const E2 = generaChiaveEpoca();
    const t = await firmaTransizione(orgId, E2, 2, 1, a.blob1, 'd1', a.firma.privateKey);
    await expect(verificaTransizione(orgId, a.E1, E2, t)).resolves.toBeUndefined();
    const fidati = await verificaChiavi(
      orgId,
      new Map([
        [1, a.E1],
        [2, E2],
      ]),
      new Map([[1, await impegno(a.E1)]]),
      [t]
    );
    expect([...fidati.keys()]).toEqual([1, 2]);
    expect(fidati.get(2)).toEqual(await impegno(E2));
  });

  test('FORGIA del server: chiave nuova chiusa per la postazione, elenco valido, nessuna firma → rifiutata', async () => {
    const a = await azienda();
    const Efalsa = generaChiaveEpoca(); // nota al server
    const ctx = { orgId, epoch: 2, kind: 'device' as const, id: 'd1' };
    const wrap = await chiudiPer(Efalsa, await pubblicaRaw(a.dev.publicKey), ctx);
    const E = await apriPer(wrap, a.dev, ctx); // HPKE da solo la apre: il controllo è la firma
    const chiavi = new Map([
      [1, a.E1],
      [2, E],
    ]);
    const fidati = new Map([[1, await impegno(a.E1)]]);
    expect(await codice(verificaChiavi(orgId, chiavi, fidati, []))).toBe('firma');
  });

  test('FORGIA del server con una firma sua: firmatario inventato, elenco precedente vero → rifiutata', async () => {
    const a = await azienda();
    const Efalsa = generaChiaveEpoca();
    const sua = await generaCoppiaFirma(false);
    const t = await firmaTransizione(orgId, Efalsa, 2, 1, a.blob1, 'd1', sua.privateKey);
    expect(await codice(verificaTransizione(orgId, a.E1, Efalsa, t))).toBe('firma');
    const t2 = await firmaTransizione(orgId, Efalsa, 2, 1, a.blob1, 'd-del-server', sua.privateKey);
    expect(await codice(verificaTransizione(orgId, a.E1, Efalsa, t2))).toBe('firma');
  });

  test('FORGIA del server con un elenco precedente inventato (MK sua) → rifiutata', async () => {
    const a = await azienda();
    const Efalsa = generaChiaveEpoca();
    const sua = await generaCoppiaFirma(false);
    const elFalso: Elenco = {
      ...a.el1,
      seq: 2,
      recipients: [
        ...a.el1.recipients,
        {
          kind: 'device',
          id: 'dx',
          userId: 'ux',
          pubKey: a.el1.recipients[0].pubKey,
          signKey: a64(await pubblicaRaw(sua.publicKey)),
          addedBy: 'ux',
          addedAt: 2,
        },
      ],
    };
    const blobFalso = await chiudiElenco(Efalsa, elFalso); // non ha E1: usa una chiave sua
    const t = await firmaTransizione(orgId, Efalsa, 2, 2, blobFalso, 'dx', sua.privateKey);
    expect(await codice(verificaTransizione(orgId, a.E1, Efalsa, t))).toBe('apertura');
  });

  test('la firma lega epoca, seq precedente, impegno, firmatario e azienda', async () => {
    const a = await azienda();
    const E2 = generaChiaveEpoca();
    const t = await firmaTransizione(orgId, E2, 2, 1, a.blob1, 'd1', a.firma.privateKey);
    const varianti: Array<[string, Transizione, Uint8Array, string]> = [
      ['epoca', { ...t, epoch: 3 }, E2, orgId],
      ['chiave', t, generaChiaveEpoca(), orgId],
      ['azienda', t, E2, 'org2'],
      ['firma', { ...t, sig: Uint8Array.from(t.sig, (b, i) => (i === 0 ? b ^ 1 : b)) }, E2, orgId],
    ];
    for (const [nome, tt, E, org] of varianti) {
      expect([nome, await codice(verificaTransizione(org, a.E1, E, tt))]).not.toEqual([
        nome,
        'accettata',
      ]);
    }
    // seq precedente dichiarata diversa da quella dell'elenco firmato → l'elenco non si apre
    expect(await codice(verificaTransizione(orgId, a.E1, E2, { ...t, prevSeq: 2 }))).toBe(
      'apertura'
    );
  });

  test('solo una voce `device` firma, anche se una voce persona porta una signKey', async () => {
    const a = await azienda();
    const el: Elenco = {
      ...a.el1,
      recipients: [{ ...a.el1.recipients[0], kind: 'person', id: 'd1' }],
    };
    const blob = await chiudiElenco(a.E1, el);
    const E2 = generaChiaveEpoca();
    const t = await firmaTransizione(orgId, E2, 2, 1, blob, 'd1', a.firma.privateKey);
    expect(await codice(verificaTransizione(orgId, a.E1, E2, t))).toBe('firma');
  });

  test('un firmatario senza signKey (voce persona) non firma', async () => {
    const a = await azienda();
    const el: Elenco = {
      ...a.el1,
      recipients: [
        {
          kind: 'person',
          id: 'u1',
          userId: 'u1',
          pubKey: a.el1.recipients[0].pubKey,
          addedBy: 'u1',
          addedAt: 1,
        },
      ],
    };
    const blob = await chiudiElenco(a.E1, el);
    const E2 = generaChiaveEpoca();
    const t = await firmaTransizione(orgId, E2, 2, 1, blob, 'u1', a.firma.privateKey);
    expect(await codice(verificaTransizione(orgId, a.E1, E2, t))).toBe('firma');
  });

  test('epoca VECCHIA sostituita dal server (impegno già noto) → rifiutata', async () => {
    const a = await azienda();
    const fidati = new Map([[1, await impegno(a.E1)]]);
    const chiavi = new Map([[1, generaChiaveEpoca()]]);
    expect(await codice(verificaChiavi(orgId, chiavi, fidati, []))).toBe('firma');
  });

  test('catena: 1 → 2 → 3; l’uscito dal 2 non firma il 3', async () => {
    const a = await azienda();
    const nuovo = await generaCoppiaFirma(false);
    const dev2 = await generaCoppia(false);
    const el1b: Elenco = {
      ...a.el1,
      seq: 2,
      recipients: [
        ...a.el1.recipients,
        {
          kind: 'device',
          id: 'd2',
          userId: 'u2',
          pubKey: a64(await pubblicaRaw(dev2.publicKey)),
          signKey: a64(await pubblicaRaw(nuovo.publicKey)),
          addedBy: 'u2',
          addedAt: 2,
        },
      ],
    };
    const blob1b = await chiudiElenco(a.E1, el1b);
    // d2 (entrata a metà dell'epoca 1) rinnova togliendo u1
    const E2 = generaChiaveEpoca();
    const t2 = await firmaTransizione(orgId, E2, 2, 2, blob1b, 'd2', nuovo.privateKey);
    const el2 = perRinnovo(el1b, { userId: 'u1' });
    const blob2 = await chiudiElenco(E2, el2);
    const E3 = generaChiaveEpoca();
    const t3buono = await firmaTransizione(orgId, E3, 3, 1, blob2, 'd2', nuovo.privateKey);
    const t3uscito = await firmaTransizione(orgId, E3, 3, 1, blob2, 'd1', a.firma.privateKey);
    const fidati = new Map([[1, await impegno(a.E1)]]);
    const chiavi = new Map([
      [1, a.E1],
      [2, E2],
      [3, E3],
    ]);
    const ok = await verificaChiavi(orgId, chiavi, fidati, [t3buono, t2]);
    expect([...ok.keys()].sort()).toEqual([1, 2, 3]);
    expect(await codice(verificaChiavi(orgId, chiavi, fidati, [t2, t3uscito]))).toBe('firma');
    // il risultato non modifica la mappa di partenza
    expect([...fidati.keys()]).toEqual([1]);
  });

  test('senza nessun impegno fidato non si accetta niente', async () => {
    const a = await azienda();
    expect(await codice(verificaChiavi(orgId, new Map([[1, a.E1]]), new Map(), []))).toBe('firma');
  });

  test('epoca senza la precedente (buco nella catena) → rifiutata', async () => {
    const a = await azienda();
    const E3 = generaChiaveEpoca();
    const t = await firmaTransizione(orgId, E3, 3, 1, a.blob1, 'd1', a.firma.privateKey);
    const chiavi = new Map([
      [1, a.E1],
      [3, E3],
    ]);
    expect(
      await codice(verificaChiavi(orgId, chiavi, new Map([[1, await impegno(a.E1)]]), [t]))
    ).toBe('firma');
  });

  test('postazione RIMOSSA nell’elenco n (seq 3) non firma n+1 su una seq vecchia, per chi ha visto la seq 3', async () => {
    const a = await azienda();
    const altra = await generaCoppiaFirma(false);
    const dev2 = await generaCoppia(false);
    // seq 2: entra d2; seq 3: d1 tolta (lo scrive un destinatario con E1)
    const el2: Elenco = {
      ...a.el1,
      seq: 2,
      recipients: [
        ...a.el1.recipients,
        {
          kind: 'device',
          id: 'd2',
          userId: 'u2',
          pubKey: a64(await pubblicaRaw(dev2.publicKey)),
          signKey: a64(await pubblicaRaw(altra.publicKey)),
          addedBy: 'u2',
          addedAt: 2,
        },
      ],
    };
    const blob2 = await chiudiElenco(a.E1, el2);
    const E2 = generaChiaveEpoca();
    // d1 firma sulla seq 2 (dove c'è ancora) mentre la postazione ha già visto la seq 3
    const t = await firmaTransizione(orgId, E2, 2, 2, blob2, 'd1', a.firma.privateKey);
    const chiavi = new Map([
      [1, a.E1],
      [2, E2],
    ]);
    const fidati = new Map([[1, await impegno(a.E1)]]);
    expect(await codice(verificaChiavi(orgId, chiavi, fidati, [t], { epoch: 1, seq: 3 }))).toBe(
      'firma'
    );
    // sull'ultima seq vista, o senza memoria, la firma della postazione presente passa
    const t3 = await firmaTransizione(orgId, E2, 2, 2, blob2, 'd2', altra.privateKey);
    await expect(
      verificaChiavi(orgId, chiavi, fidati, [t3], { epoch: 1, seq: 2 })
    ).resolves.toBeDefined();
    await expect(verificaChiavi(orgId, chiavi, fidati, [t])).resolves.toBeDefined();
  });
});
