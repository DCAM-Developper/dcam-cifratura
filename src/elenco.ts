// src/elenco.ts
// Elenco dei destinatari — protocollo §3.5, §4.5.
import { aad, cifraAes, decifraAes, scriviBusta, leggiBusta } from './formato';
import { chiaveElenco, chiudiPer } from './chiavi';
import { da64 } from './bytes';
import { ErroreRiservata } from './errori';

export type Destinatario = {
  kind: 'person' | 'device';
  id: string;
  userId: string;
  label?: string;
  pubKey: string;
  addedBy: string;
  addedAt: number;
};
export type Elenco = {
  v: 1;
  orgId: string;
  epoch: number;
  seq: number;
  recovery: { pubKey: string };
  recipients: Destinatario[];
};

const aadElenco = (orgId: string, epoch: number, seq: number) => aad('manifest', orgId, epoch, seq);

export async function chiudiElenco(E: Uint8Array, el: Elenco): Promise<Uint8Array> {
  const { nonce, cifrato } = await cifraAes(
    await chiaveElenco(E),
    new TextEncoder().encode(JSON.stringify(el)),
    aadElenco(el.orgId, el.epoch, el.seq)
  );
  return scriviBusta('DCM1', new Uint8Array(0), nonce, cifrato);
}

export async function apriElenco(
  E: Uint8Array,
  busta: Uint8Array,
  atteso: { orgId: string; epoch: number; seq: number }
): Promise<Elenco> {
  const { nonce, cifrato } = leggiBusta('DCM1', busta, 0);
  const pt = await decifraAes(
    await chiaveElenco(E),
    nonce,
    cifrato,
    aadElenco(atteso.orgId, atteso.epoch, atteso.seq)
  );
  const el = JSON.parse(new TextDecoder().decode(pt)) as Elenco;
  if (
    el.v !== 1 ||
    el.orgId !== atteso.orgId ||
    el.epoch !== atteso.epoch ||
    el.seq !== atteso.seq
  ) {
    throw new ErroreRiservata('elenco', 'elenco incoerente con ciò che il server dichiara');
  }
  return el;
}

const chiave = (d: Destinatario) => `${d.kind}:${d.id}`;

export function conAggiunti(el: Elenco, nuovi: Destinatario[]): Elenco {
  const visti = new Set(el.recipients.map(chiave));
  return {
    ...el,
    seq: el.seq + 1,
    recipients: [...el.recipients, ...nuovi.filter(d => !visti.has(chiave(d)))],
  };
}

export function perRinnovo(el: Elenco, togli: { userId?: string; deviceId?: string }): Elenco {
  return {
    ...el,
    epoch: el.epoch + 1,
    seq: 1,
    recipients: el.recipients.filter(d => {
      if (togli.userId && d.userId === togli.userId) return false;
      if (togli.deviceId && d.kind === 'device' && d.id === togli.deviceId) return false;
      return true;
    }),
  };
}

export async function chiusurePerEpoca(
  E: Uint8Array,
  el: Elenco
): Promise<Array<{ kind: 'person' | 'device' | 'recovery'; id: string; wrapped: Uint8Array }>> {
  const out: Array<{ kind: 'person' | 'device' | 'recovery'; id: string; wrapped: Uint8Array }> =
    [];
  for (const d of el.recipients) {
    out.push({
      kind: d.kind,
      id: d.id,
      wrapped: await chiudiPer(E, da64(d.pubKey), {
        orgId: el.orgId,
        epoch: el.epoch,
        kind: d.kind,
        id: d.id,
      }),
    });
  }
  out.push({
    kind: 'recovery',
    id: 'recovery',
    wrapped: await chiudiPer(E, da64(el.recovery.pubKey), {
      orgId: el.orgId,
      epoch: el.epoch,
      kind: 'recovery',
      id: 'recovery',
    }),
  });
  return out;
}
