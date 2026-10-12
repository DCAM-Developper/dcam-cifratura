// src/firma.ts
// Epoche firmate — protocollo §3.6, §4.5.
// Una chiave d'epoca E_{n+1} vale solo se una POSTAZIONE dell'elenco n (autenticato con MK_n) ha
// firmato il suo impegno. Il server ha tutte le pubbliche e può chiudere per una postazione una
// chiave che conosce lui; non ha nessuna privata di firma, e non può scrivere un elenco n
// autenticato. La catena parte da un'ancora che il server non controlla (§3.6).
import { ab, a64, da64 } from './bytes';
import { aad, PREFISSO_AAD } from './formato';
import { apriElenco } from './elenco';
import { ErroreRiservata } from './errori';

/** ECDSA P-256 con SHA-256 (WebCrypto): firma di 64 byte (r || s). */
export const CURVA_FIRMA = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ALG_FIRMA = { name: 'ECDSA', hash: 'SHA-256' } as const;
const FIRMA = 64;

/** Coppia di firma di una postazione: in uso reale la privata è NON estraibile, come D_d. */
export async function generaCoppiaFirma(estraibile: boolean): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(CURVA_FIRMA, estraibile, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
}

/** Impegno della chiave d'epoca: HKDF(E, info "<prefisso>.commit"), 32 byte; non rivela E. */
export async function impegno(E: Uint8Array): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', ab(E), 'HKDF', false, ['deriveBits']);
  const bit = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new ArrayBuffer(0),
      info: new TextEncoder().encode(`${PREFISSO_AAD}.commit`),
    },
    base,
    256
  );
  return new Uint8Array(bit);
}

/** Il passaggio n → n+1 (`epoch` = n+1), come lo conserva il server accanto all'elenco n+1. */
export type Transizione = {
  epoch: number;
  /** seq dell'elenco n su cui il rinnovo si è basato */
  prevSeq: number;
  /** busta DCM2 dell'elenco n alla seq `prevSeq` */
  prevBlob: Uint8Array;
  /** id della postazione che firma: deve stare in quell'elenco, con `signKey` */
  signerId: string;
  sig: Uint8Array;
};

async function messaggio(
  orgId: string,
  epoch: number,
  prevSeq: number,
  imp: Uint8Array,
  prevBlob: Uint8Array,
  signerId: string
): Promise<Uint8Array> {
  if (epoch < 2) throw new ErroreRiservata('formato', 'una transizione parte dall’epoca 2');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', ab(prevBlob)));
  return aad('transition', orgId, epoch, prevSeq, a64(imp), a64(h), signerId);
}

export async function firmaTransizione(
  orgId: string,
  Enuova: Uint8Array,
  epoch: number,
  prevSeq: number,
  prevBlob: Uint8Array,
  signerId: string,
  privFirma: CryptoKey
): Promise<Transizione> {
  const m = await messaggio(orgId, epoch, prevSeq, await impegno(Enuova), prevBlob, signerId);
  const sig = new Uint8Array(await crypto.subtle.sign(ALG_FIRMA, privFirma, ab(m)));
  return { epoch, prevSeq, prevBlob, signerId, sig };
}

const rifiuta = (perche: string) => new ErroreRiservata('firma', perche);

/**
 * Verifica che `Enuova` sia la chiave dell'epoca `t.epoch` firmata da una postazione dell'elenco
 * precedente, aperto con `Eprec` (che chi chiama ha già verificato). Errori: `apertura`/`elenco`
 * se l'elenco precedente non è autentico, `firma` se il firmatario o la firma non tornano.
 * Restituisce la `signKey` (base64url) con cui la firma si è verificata.
 */
export async function verificaTransizione(
  orgId: string,
  Eprec: Uint8Array,
  Enuova: Uint8Array,
  t: Transizione
): Promise<string> {
  const el = await apriElenco(Eprec, t.prevBlob, {
    orgId,
    epoch: t.epoch - 1,
    seq: t.prevSeq,
  });
  const chi = el.recipients.find(d => d.kind === 'device' && d.id === t.signerId);
  if (!chi?.signKey)
    throw rifiuta(`la postazione ${t.signerId} non può firmare l'epoca ${t.epoch}`);
  if (t.sig.length !== FIRMA) throw rifiuta('firma di lunghezza inattesa');
  const pub = await crypto.subtle.importKey('raw', ab(da64(chi.signKey)), CURVA_FIRMA, false, [
    'verify',
  ]);
  const m = await messaggio(
    orgId,
    t.epoch,
    t.prevSeq,
    await impegno(Enuova),
    t.prevBlob,
    t.signerId
  );
  if (!(await crypto.subtle.verify(ALG_FIRMA, pub, ab(t.sig), ab(m)))) {
    throw rifiuta(`la chiave dell'epoca ${t.epoch} non è firmata da una postazione dell'azienda`);
  }
  return chi.signKey;
}

const uguali = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/** Ciò che la postazione ricorda oltre agli impegni (protocollo §3.6). */
export type Memoria = {
  /**
   * L'elenco più recente che questa postazione ha già aperto: una transizione dall'epoca
   * `visto.epoch` deve essere firmata su quella seq o una successiva. NON ferma chi conosce
   * E_n (scrive un elenco n a una seq più alta con una postazione sua): protegge solo da una
   * postazione tolta dentro un'epoca senza rinnovo, che DCAM non produce (§1).
   */
  visto?: { epoch: number; seq: number };
  /**
   * Epoca → (id della postazione → `signKey`) di chi può firmarla: chi rinnova n → n+1 le fissa
   * PRIMA di inviare (le postazioni con `signKey` dell'elenco n da cui parte, meno quelle che
   * toglie). Conta la COPPIA: chi conosce E_n può scrivere un elenco n con un id noto e una
   * `signKey` sua. Una n+1 firmata da un'altra (la tolta, una postazione coniata, o un id noto
   * con una chiave diversa) si rifiuta.
   */
  firmatari?: Map<number, ReadonlyMap<string, string>>;
};

/**
 * Accetta le chiavi d'epoca solo se tornano con la catena (protocollo §3.6).
 * `fidati` = impegni già verificati (epoca → 32 byte): l'ancora, o ciò che la postazione ha
 * accettato in passato. Ogni chiave di un'epoca nota deve avere lo stesso impegno (anche le
 * VECCHIE: altrimenti il server inietterebbe oggetti in un'epoca passata); ogni epoca nuova deve
 * avere la precedente verificata e una transizione firmata (da uno dei `firmatari` dell'epoca,
 * se la memoria li fissa). Restituisce una mappa NUOVA con gli impegni verificati; `fidati` non
 * si modifica.
 */
export async function verificaChiavi(
  orgId: string,
  chiavi: Map<number, Uint8Array>,
  fidati: Map<number, Uint8Array>,
  transizioni: Transizione[],
  memoria: Memoria = {}
): Promise<Map<number, Uint8Array>> {
  const { visto, firmatari } = memoria;
  const out = new Map(fidati);
  const perEpoca = new Map(transizioni.map(t => [t.epoch, t]));
  for (const e of [...chiavi.keys()].sort((a, b) => a - b)) {
    const E = chiavi.get(e)!;
    const c = await impegno(E);
    const noto = out.get(e);
    if (noto) {
      if (!uguali(c, noto)) throw rifiuta(`la chiave dell'epoca ${e} non è quella accettata`);
      continue;
    }
    // e-1 è già passata da questo ciclo (ordine crescente): se c'è, è verificata
    const prec = chiavi.get(e - 1);
    const t = perEpoca.get(e);
    if (!prec || !t) throw rifiuta(`l'epoca ${e} non si lega alla precedente`);
    if (visto && visto.epoch === e - 1 && t.prevSeq < visto.seq) {
      throw rifiuta(`l'epoca ${e} è firmata su un elenco più vecchio di quello già visto`);
    }
    const signKey = await verificaTransizione(orgId, prec, E, t);
    const possibili = firmatari?.get(e);
    if (possibili && possibili.get(t.signerId) !== signKey) {
      throw rifiuta(`l'epoca ${e} è firmata da ${t.signerId}, non da chi l'ha rinnovata`);
    }
    out.set(e, c);
  }
  return out;
}
