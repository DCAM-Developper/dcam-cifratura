// Genera vettori/v2.json: buste prodotte UNA volta dal codice 0.2.0 con chiavi fisse.
// I vettori non si rigenerano: se il formato cambia, si aggiunge v3.json e v2 resta come prova
// che le buste vecchie si aprono ancora. Uso: node vettori/genera.mjs (dopo npm run build).
// (I vettori v1 della 0.1.0, mai pubblicata, sono nella storia git: la v2 non li apre.)
import { writeFileSync, existsSync } from 'node:fs';
import * as R from '../dist/index.js';

const OUT = new URL('./v2.json', import.meta.url);
if (existsSync(OUT) && !process.argv.includes('--sovrascrivi')) {
  console.error('v2.json esiste già: i vettori non si rigenerano (--sovrascrivi solo prima della 0.2.0).');
  process.exit(1);
}
const hex = b => Buffer.from(b).toString('hex');
const byteFissi = (n, s) => Uint8Array.from({ length: n }, (_, i) => (i * 7 + s) & 0xff);

const E = byteFissi(32, 1);
const ind = { orgId: 'org-esempio', kind: 'part', objectId: 'obj-1', rev: 3 };
const epoch = 7;
const meta = { nome: 'flangia', spessore: 3 };
const body = new TextEncoder().encode('0123456789'.repeat(50));

// coppia fissa del destinatario (persona/postazione/custodia di prova): esportata in PKCS#8
const coppia = await R.generaCoppia(true);
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', coppia.privateKey));
const pub = await R.pubblicaRaw(coppia.publicKey);
const ctx = { orgId: ind.orgId, epoch, kind: 'device', id: 'dev-1' };
const firma = await R.generaCoppiaFirma(true);
const firmaPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', firma.privateKey));
const signKey = R.a64(await R.pubblicaRaw(firma.publicKey));

const elenco = {
  v: 2, orgId: ind.orgId, epoch, seq: 2,
  recovery: { pubKey: R.a64(pub) },
  recipients: [{ kind: 'device', id: 'dev-1', userId: 'u-1', pubKey: R.a64(pub), signKey, addedBy: 'u-1', addedAt: 1700000000000 }],
};
const elencoBusta = await R.chiudiElenco(E, elenco);
const Enuova = byteFissi(32, 2);
const tr = await R.firmaTransizione(ind.orgId, Enuova, epoch + 1, 2, elencoBusta, 'dev-1', firma.privateKey);

const frase = 'una frase lunga di prova';
const kdf = { ...R.PARAMETRI_KDF, salt: R.a64(byteFissi(16, 9)) };
const persona = await R.creaPersona(ind.orgId, 'u-1', frase, kdf);

const ancora = await R.impegno(E);
const rec = await R.creaRecupero(ind.orgId, ancora);

const codice = 'ABCDEFGHJKMNPQRSTVWX';
const pacchetto = { orgId: ind.orgId, forUserId: 'u-2', epochs: { [epoch]: R.a64(E) }, manifest: { epoch, seq: 2, blob: 'x' } };

const v = {
  versione: '0.2.0',
  nota: 'Buste del protocollo v2 prodotte con chiavi fisse. Ogni implementazione deve aprirle.',
  aad: { campi: ['obj', ind.orgId, ind.kind, ind.objectId, ind.rev, 'meta', epoch], hex: hex(R.aad('obj', ind.orgId, ind.kind, ind.objectId, ind.rev, 'meta', epoch)) },
  chiaveEpoca: hex(E),
  indirizzo: ind,
  epoca: epoch,
  DCR2_meta: { json: meta, busta: hex(await R.chiudiJson(E, epoch, ind, 'meta', meta)) },
  DCR2_body: { testo: new TextDecoder().decode(body), busta: hex(await R.chiudiParte(E, epoch, ind, 'body', body)) },
  DCM2: { elenco, busta: hex(elencoBusta) },
  impegno: { chiave: hex(E), impegno: hex(ancora) },
  transizione: { chiaveNuova: hex(Enuova), epoch: tr.epoch, prevSeq: tr.prevSeq, signerId: tr.signerId, sig: hex(tr.sig), firmaPkcs8: hex(firmaPkcs8) },
  destinatario: { pkcs8: hex(pkcs8), pub: hex(pub) },
  chiusura: { contesto: ctx, chiusa: hex(await R.chiudiPer(E, pub, ctx)) },
  DCS2_persona: { orgId: ind.orgId, userId: 'u-1', frase, record: persona.record },
  recupero: { orgId: ind.orgId, R: hex(rec.R), ancora: hex(ancora), pub: hex(rec.pubKey), sealedPriv: hex(rec.sealedPriv), parti: rec.parti.map(hex) },
  custodia: { orgId: ind.orgId, parteB: hex(rec.parti[1]), chiusa: hex(await R.chiudiPerCustodia(rec.parti[1], ind.orgId, rec.pubKey, pub)) },
  DCS2_trasferimento: { codice, transferId: 't-1', orgId: ind.orgId, forUserId: 'u-2', pacchetto, busta: hex(await R.chiudiTrasferimento(codice, 't-1', ind.orgId, 'u-2', pacchetto)) },
};
writeFileSync(OUT, JSON.stringify(v, null, 2) + '\n');
console.log('scritto', OUT.pathname);
