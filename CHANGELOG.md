# Changelog

## 0.2.0 — 2026-10

Protocollo **v2**. Non apre le buste v1 (la 0.1.0 non è mai stata pubblicata; nessun dato v1 in
produzione). Vettori nuovi in `vettori/v2.json`.

- **Epoche firmate (SPEC §3.6).** Con la v1 chi poteva scrivere sul server poteva chiudere per una
  postazione una chiave d'epoca scelta da lui (HPKE in modo base) e un elenco autenticato con
  quella chiave: la postazione l'avrebbe adottata. Ora ogni postazione ha una coppia di firma
  ECDSA P-256 (`signKey` nell'elenco); una chiave d'epoca nuova vale solo con una transizione
  firmata da una postazione dell'elenco precedente, e le chiavi già accettate si confrontano col
  loro impegno. L'ancora viene dalla postazione che attiva, dal pacchetto chiuso col codice di
  trasferimento o da dentro la privata di recupero. Nuove funzioni `impegno`,
  `generaCoppiaFirma`, `firmaTransizione`, `verificaTransizione`, `verificaChiavi`; nuovo codice
  d'errore `firma`. `verificaChiavi(…, visto)` rifiuta una transizione firmata su una seq
  dell'elenco più vecchia di quella già vista.
- `creaRecupero(orgId, ancora)` / `apriRecupero` → `{ coppia, ancora }`; l'AAD lega la pubblica di RP.
- Custodia: l'info HPKE lega la pubblica di RP (una parte B di un kit vecchio non passa per quella
  del nuovo); `apriPerCustodia` controlla la lunghezza (114 byte) e dà `ErroreRiservata`.
- Persona: l'AAD lega pubblica e parametri Argon2id; chi apre accetta solo `ops` 1-10,
  `mem` 8-256 MiB, sale di 16 byte.
- Decompressione con tetto di 256 MiB in uscita (`TETTO_DECOMPRESSO`).
- `daBase32` lancia `ErroreRiservata('formato')`.
- Test anche in WebKit; coppie ECDH ed ECDSA non estraibili provate attraverso IndexedDB.

## 0.1.0 — 2026-10

Prima pubblicazione. Il codice è quello in uso in DCAM (protocollo v1), con i commenti ripuliti
dai riferimenti interni; il comportamento è invariato (stesso JavaScript una volta tolti i
commenti, verificabile con `strumenti/stesso-codice.mjs`).

- Buste `DCR1` (oggetti), `DCS1` (chiusura simmetrica), `DCM1` (elenco dei destinatari).
- Chiusura delle chiavi d'epoca con HPKE (RFC 9180, DHKEM P-256).
- Chiave personale da frase con Argon2id; recupero con Shamir 2-di-3 e chiave di custodia.
- Vettori di prova fissi (`vettori/v1.json`), test in Node e in Chromium.
- La chiave di custodia è ancora quella di **sviluppo** (`CUSTODIA_SVILUPPO = true`).

- Licenza Apache-2.0 (con concessione esplicita sui brevetti).

La 1.0.0 arriverà dopo una revisione di sicurezza esterna.
