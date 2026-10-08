# Changelog

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
