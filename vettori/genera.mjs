// Genera vettori/v1.json: buste prodotte UNA volta dal codice 0.1.0 con chiavi fisse.
// I vettori non si rigenerano: se il formato cambia, si aggiunge v2.json e v1 resta come prova
// che le buste vecchie si aprono ancora. Uso: node vettori/genera.mjs (dopo npm run build).
import { writeFileSync, existsSync } from 'node:fs';
import * as R from '../dist/index.js';

const OUT = new URL('./v1.json', import.meta.url);
if (existsSync(OUT) && !process.argv.includes('--sovrascrivi')) {
  console.error('v1.json esiste già: i vettori non si rigenerano (--sovrascrivi solo prima della 0.1.0).');
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

const elenco = {
  v: 1, orgId: ind.orgId, epoch, seq: 2,
  recovery: { pubKey: R.a64(pub) },
  recipients: [{ kind: 'device', id: 'dev-1', userId: 'u-1', pubKey: R.a64(pub), addedBy: 'u-1', addedAt: 1700000000000 }],
};

const frase = 'una frase lunga di prova';
const kdf = { ...R.PARAMETRI_KDF, salt: R.a64(byteFissi(16, 9)) };
const persona = await R.creaPersona(ind.orgId, 'u-1', frase, kdf);

const rec = await R.creaRecupero(ind.orgId);

const codice = 'ABCDEFGHJKMNPQRSTVWX';
const pacchetto = { orgId: ind.orgId, forUserId: 'u-2', epochs: { [epoch]: R.a64(E) }, manifest: { epoch, seq: 2, blob: 'x' } };

const v = {
  versione: '0.1.0',
  nota: 'Buste del protocollo v1 prodotte con chiavi fisse. Ogni implementazione deve aprirle.',
  aad: { campi: ['obj', ind.orgId, ind.kind, ind.objectId, ind.rev, 'meta', epoch], hex: hex(R.aad('obj', ind.orgId, ind.kind, ind.objectId, ind.rev, 'meta', epoch)) },
  chiaveEpoca: hex(E),
  indirizzo: ind,
  epoca: epoch,
  DCR1_meta: { json: meta, busta: hex(await R.chiudiJson(E, epoch, ind, 'meta', meta)) },
  DCR1_body: { testo: new TextDecoder().decode(body), busta: hex(await R.chiudiParte(E, epoch, ind, 'body', body)) },
  DCM1: { elenco, busta: hex(await R.chiudiElenco(E, elenco)) },
  destinatario: { pkcs8: hex(pkcs8), pub: hex(pub) },
  chiusura: { contesto: ctx, chiusa: hex(await R.chiudiPer(E, pub, ctx)) },
  DCS1_persona: { orgId: ind.orgId, userId: 'u-1', frase, record: persona.record },
  recupero: { orgId: ind.orgId, R: hex(rec.R), pub: hex(rec.pubKey), sealedPriv: hex(rec.sealedPriv), parti: rec.parti.map(hex) },
  custodia: { orgId: ind.orgId, parteB: hex(rec.parti[1]), chiusa: hex(await R.chiudiPerCustodia(rec.parti[1], ind.orgId, pub)) },
  DCS1_trasferimento: { codice, transferId: 't-1', orgId: ind.orgId, forUserId: 'u-2', pacchetto, busta: hex(await R.chiudiTrasferimento(codice, 't-1', ind.orgId, 'u-2', pacchetto)) },
};
writeFileSync(OUT, JSON.stringify(v, null, 2) + '\n');
console.log('scritto', OUT.pathname);
