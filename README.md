# @dcam/cifratura

Il cuore crittografico di [DCAM](https://thedcamproject.com): il codice che cifra nel browser i
disegni, i pezzi e i nesting di un'azienda, in modo che il server li conservi senza poterli leggere.

*English summary below.*

> **Stato: 0.3.0, non ancora revisionato da terzi.** Il codice è quello in uso in DCAM. Una
> revisione di sicurezza esterna è prevista; fino ad allora nessuna affermazione di
> «certificazione» o «verifica indipendente» vale per questo pacchetto.

## Cosa fa

- Cifra ogni versione di un oggetto (metadati, miniatura, contenuto) con AES-256-GCM, legata da un
  AAD a organizzazione, tipo, oggetto, revisione ed epoca: il server non può spostare o scambiare
  un testo cifrato senza che l'apertura fallisca. Busta `DCR2`.
- Chiude la chiave d'azienda di ogni epoca per ciascun destinatario (persona, postazione,
  recupero) con **HPKE (RFC 9180)** su P-256.
- Autentica l'elenco dei destinatari (busta `DCM2`): il server non può aggiungere qualcuno.
- Accetta una chiave d'epoca nuova solo se una postazione dell'epoca precedente l'ha firmata
  (ECDSA P-256): il server non può far adottare una chiave scelta da lui.
- Ricava la chiave personale da una frase con **Argon2id** e chiude con essa la chiave privata
  della persona (busta `DCS2`).
- Divide la chiave di recupero in 3 parti con **Shamir 2-di-3**; una parte è chiusa per la chiave
  di custodia di DCAM.
- Cambia epoca quando una persona esce: i dati scritti dopo non si aprono con le chiavi vecchie.

## Cosa NON fa

- **Non protegge dal codice servito**: il browser esegue il JavaScript che riceve. Un server
  compromesso può servire codice diverso da questo. Pubblicarlo serve a poterlo confrontare.
- Non nasconde i metadati elencati in [SPEC.md §7](SPEC.md#7-cosa-resta-in-chiaro-sul-server)
  (chi lavora in quale azienda, quanti oggetti, quando, quanto sono grandi).
- Non garantisce la disponibilità: il server può rifiutarsi di consegnare o consegnare una versione
  vecchia (il rollback si rileva solo rispetto a ciò che il browser ha già visto).
- Non fa rete e non salva niente: rotte, archiviazione e interfaccia sono dell'applicazione.
- Non contiene crittografia scritta da noi: solo WebCrypto, `@hpke/core`, libsodium (Argon2id) e
  `shamir-secret-sharing`.

Il modello di minaccia completo è in [SPEC.md §1](SPEC.md#1-modello-di-minaccia).

## Come si verifica

```bash
npm ci
npx playwright install chromium webkit
npm run typecheck
npm test          # gli stessi test in Node, Chromium e WebKit
```

- `src/*.test.ts` sono i test del codice; quelli che usano `node:crypto` e `node:zlib` come
  **oracolo indipendente** (AES-GCM, HKDF e inflate ricalcolati senza passare dal pacchetto)
  girano solo in Node.
- `vettori/v2.json` contiene buste prodotte con chiavi note; `vettori/v2.test.ts` le apre in
  tutti gli ambienti. Un'altra implementazione del protocollo deve aprirle allo stesso modo.
- `strumenti/stesso-codice.mjs a.ts b.ts` dice se due file differiscono solo nei commenti: serve a
  confrontare questi sorgenti con quelli inclusi nell'applicazione.

## Uso

Il pacchetto per ora si distribuisce solo da questo repository, non da npm: `package.json` ha
`"private": true` proprio per impedire una pubblicazione per errore, e si toglierà il giorno in cui
lo pubblicheremo su npm. Per usarlo: clonare il repository, `npm ci && npm run build`.

```ts
import { generaChiaveEpoca, chiudiJson, apriJson } from '@dcam/cifratura';

const E = generaChiaveEpoca();
const ind = { orgId: 'org', kind: 'part', objectId: crypto.randomUUID(), rev: 1 };
const busta = await chiudiJson(E, 1, ind, 'meta', { nome: 'flangia' });
const meta = await apriJson(e => (e === 1 ? E : undefined), ind, 'meta', busta);
```

Un solo ingresso per browser e Node (≥ 20.19): il codice usa solo API standard del web
(`crypto.subtle`, `crypto.getRandomValues`, `CompressionStream`).

Gli errori del protocollo sono `ErroreRiservata` con un `codice` (`formato`, `apertura`, `elenco`,
`epoca`, `frase`, `parti`, `firma`, …): l'applicazione sceglie la frase da mostrare, i test controllano il
codice.

## Documenti

- [SPEC.md](SPEC.md) — il protocollo v2 (normativo).
- [SECURITY.md](SECURITY.md) — come segnalare un problema.
- [CHANGELOG.md](CHANGELOG.md).

## Licenza

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Dipendenze: `@hpke/core` (MIT), `libsodium-wrappers-sumo` (ISC),
`shamir-secret-sharing` (Apache-2.0).

---

## English summary

`@dcam/cifratura` is the end-to-end encryption core used by DCAM, a browser-based 2D CAD/CAM.
Company data is encrypted in the user's browser; the server stores ciphertext it cannot read.

- AES-256-GCM object envelopes (`DCR2`) bound by AAD to organization, kind, object, revision and
  epoch; per-epoch company keys wrapped for each recipient with HPKE (RFC 9180, DHKEM P-256);
  an authenticated recipient list (`DCM2`); passphrase keys via Argon2id (`DCS2`); recovery key
  split 2-of-3 with Shamir. A new epoch key is accepted only if a device of the previous epoch
  signed it (ECDSA P-256), so the server cannot make devices adopt a key it chose.
- Only standard primitives from established libraries; no custom cryptography.
- **Not protected against:** a compromised server serving modified JavaScript (the inherent limit
  of in-browser E2EE — publishing this code is what makes comparison possible), metadata listed in
  SPEC §7, availability/rollback beyond what the browser has already seen.
- **Status: 0.3.0, not yet externally audited.** 1.0.0 will follow an external review.
- Distributed from this repository only, not from npm for now (`"private": true` in `package.json`
  prevents an accidental publish): clone, then `npm ci && npm run build`.
- The specification ([SPEC.md](SPEC.md)) and identifiers are in Italian; JSON field names are in
  English. Test vectors in `vettori/v2.json`. Report vulnerabilities as described in
  [SECURITY.md](SECURITY.md).
