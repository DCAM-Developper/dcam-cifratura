# Sicurezza / Security

## Segnalare una vulnerabilità

Non aprire una issue pubblica. Usa la **segnalazione privata di GitHub** («Report a
vulnerability» nella scheda *Security* di questo repository).

Indica, se puoi: la versione o il commit, cosa hai osservato, come riprodurlo (idealmente un test
o un vettore), e l'impatto che ipotizzi. Rispondiamo entro 7 giorni lavorativi con una prima
valutazione. Chi segnala viene citato nel CHANGELOG, se lo desidera.

Rientrano: difetti del codice in `src/`, divergenze fra codice e [SPEC.md](SPEC.md), debolezze
del protocollo, vettori che si aprono dove non dovrebbero (o viceversa).

Non rientrano qui (vanno segnalati a DCAM per i suoi canali): il sito, il server, l'interfaccia.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's **private vulnerability reporting** ("Report a
vulnerability" in this repository's *Security* tab). Include the version or commit, what you
observed, how to reproduce it (ideally a test or vector), and the impact you expect. We reply
within 7 business days.

## Stato

Versione 0.x: **nessuna revisione esterna ancora**. Il limite principale, dichiarato, è il codice
servito al browser: vedi [SPEC.md §1](SPEC.md#1-modello-di-minaccia).
