# Changelog

## 0.3.0 — 2026-10

Protocollo **v2** invariato nei formati (stessi vettori `vettori/v2.json`); cambia la verifica delle
epoche e la sua API. Viene da una revisione indipendente della 0.2.0.

- **Chi rinnova non adotta la biforcazione della tolta (SPEC §3.6, §4.5).** Con la 0.2.0 una
  postazione tolta, insieme al server, firmava un'epoca *n+1* sua (era nell'elenco *n*) e la faceva
  adottare a tutti, anche a chi aveva appena rinnovato: la revoca si aggirava. Ora chi rinnova fissa
  prima di inviare i **firmatari** possibili di *n+1* (coppie id → `signKey`: un id noto con una
  chiave diversa non passa) e, alla risposta, ne salva l'impegno.
- **API:** `verificaChiavi(orgId, chiavi, fidati, transizioni, memoria?)` con
  `memoria = { visto?, firmatari? }` (prima il quinto argomento era `visto`). Nuovo tipo `Memoria`.
  `verificaTransizione` restituisce la `signKey` con cui la firma si è verificata (prima `void`).
- **SPEC §1:** i limiti della catena con il server complice in una tabella (L1-L6): firmare vale
  quanto conoscere `E_n`; il controllo della seq vista protegge un caso che DCAM non produce; il
  recupero su un browser nuovo parte solo da C_1; la revoca dichiarata dal server; un rinnovo
  concorrente di una postazione appena entrata; malleabilità ECDSA.
- **SPEC §1, invariante:** la memoria della postazione cresce e basta, solo l'attivazione la
  azzera; ogni aggiornamento in un'unica transazione (due schede dello stesso browser).
- **SPEC §3.6, §5.1:** la memoria della postazione (seq vista, firmatari, impegni) è un obbligo di
  chi applica il protocollo: va passata su tutte le strade, compreso il recupero 3-4 su un browser
  che ha già usato l'azienda, e riletta con le epoche come numeri. Firmatari fissati vuoti per
  un'epoca non lasciano firmare nessuno (test).
- **SPEC §1, L1:** il rimedio alla biforcazione segnalata da chi ha rinnovato è riattivare
  l'azienda (`E_1` nuova).

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
