# Protocollo di cifratura DCAM — versione 2

**Stato:** normativo per il codice di questo repository (`@dcam/cifratura` 0.2.x).
**Lingua:** italiano; gli identificatori del codice sono in italiano, i nomi dei campi JSON in inglese.

Questo documento descrive come DCAM cifra i dati di un'azienda nel browser di chi li usa, in modo
che il server li conservi senza poterli leggere. Il codice in `src/` lo implementa; i test e i
vettori in `vettori/` lo verificano. Se codice e documento divergono, è un difetto: si segnala
(vedi `SECURITY.md`).

I rimandi «protocollo §x» nei commenti del codice si riferiscono alle sezioni di questo documento.

---

## 0. Principi

1. **Fuori dal browser del cliente esistono solo dati cifrati.** Il server conserva, numera e
   consegna; non apre.
2. **Nessuna primitiva crittografica scritta da noi.** Solo primitive standard da librerie
   diffuse, montate in costruzioni standard:

   | Funzione | Primitiva | Libreria |
   |---|---|---|
   | cifratura dei dati e delle chiavi simmetriche | AES-256-GCM, nonce casuale 96 bit, tag 128 bit | WebCrypto |
   | derivazione di sottochiavi | HKDF-SHA256 (RFC 5869) | WebCrypto |
   | chiusura di una chiave per un destinatario | **HPKE RFC 9180**, modo base, suite DHKEM(P-256, HKDF-SHA256) · HKDF-SHA256 · AES-256-GCM | `@hpke/core` (sopra WebCrypto) |
   | firma del passaggio a un'epoca nuova | **ECDSA P-256 con SHA-256**, firma di 64 byte (r ‖ s) | WebCrypto |
   | impronta di contenuti (elenco precedente) | SHA-256 | WebCrypto |
   | chiave personale da una frase | **Argon2id** (RFC 9106) | `libsodium-wrappers-sumo`, `crypto_pwhash` |
   | divisione della chiave di recupero | **Shamir 2-di-3** su GF(2^8) | `shamir-secret-sharing` |
   | casualità | `crypto.getRandomValues` | WebCrypto |

   **Perché P-256 e non X25519.** La chiave di una postazione deve sopravvivere alla ricarica
   della pagina restando **non estraibile**. Misurato su WebKit (motore di Safari): una
   `CryptoKey` X25519 salvata in IndexedDB torna `null` dopo la ricarica, una ECDH P-256 non
   estraibile torna intera. P-256 ha sicurezza equivalente (~128 bit) ed è standard NIST.
   Le coppie ECDH ed ECDSA P-256 non estraibili salvate in IndexedDB e rilette da una connessione
   nuova funzionano in Chromium e in WebKit (test `src/idb.browser.test.ts`); Safari su macOS e
   iPad non è ancora stato provato direttamente.

   **Perché una coppia di firma separata.** La coppia ECDH di una postazione serve solo a ricevere
   chiusure; la firma usa una seconda coppia ECDSA. Non si usa la stessa chiave per due algoritmi.

3. **Semplicità prima dell'eleganza:** un solo formato di busta per gli oggetti, un solo modo di
   chiudere una chiave per un destinatario, un solo modo di autenticare un elenco.
4. **Ogni byte autenticato dice dove sta:** ogni cifratura porta un AAD che la lega a
   organizzazione, tipo, oggetto, revisione ed epoca. Il server non può spostare un testo cifrato
   da un posto a un altro senza che l'apertura fallisca.

## 1. Modello di minaccia

**Il protocollo difende da:**

- chi **legge** il server (operatore, furto del database o dei backup, intrusione, richiesta di
  un terzo al gestore del servizio): non deve poter leggere i contenuti. La §7 elenca cosa vede
  comunque;
- chi **scrive** sul server: non deve poter falsificare né scambiare contenuti o chiavi senza che
  il browser se ne accorga (l'apertura fallisce con un errore dichiarato). In particolare non può
  far adottare a una postazione una chiave d'epoca scelta da lui: ogni epoca nuova deve essere
  firmata da una postazione dell'epoca precedente (§3.6). La HPKE in modo base, da sola, non lo
  impedisce: chiunque abbia la pubblica di un destinatario gli può chiudere una chiave;
- una **persona uscita** dall'azienda: non apre i dati scritti dopo la sua uscita (§4.5).

**Il protocollo NON difende da (limiti dichiarati):**

- **il codice servito.** Il browser esegue il JavaScript che il server gli manda: un server
  compromesso che serve codice modificato può leggere i dati mentre l'utente lavora. È il limite
  di ogni cifratura end-to-end nel browser. Pubblicare questo codice permette di confrontarlo con
  quello servito; non elimina il limite;
- **la disponibilità.** Il server può rifiutarsi di consegnare, cancellare, o consegnare una
  revisione vecchia invece della più recente. Il browser rileva il rollback solo rispetto a ciò
  che ha già visto (§6.4);
- **ciò che una persona ha già letto:** chi esce può aver copiato i dati che apriva;
- **la postazione sbloccata:** chi siede a una postazione autorizzata con la sessione aperta
  legge come il titolare della postazione;
- **i metadati** della §7 e le **dimensioni** dei testi cifrati (nessun riempimento in v2);
- **il recupero è nella fiducia di chi ha le parti.** Chi ricompone `R` (il kit, o due parti su
  tre) apre tutte le epoche e può entrare come una persona nuova. L'ancora del recupero (§3.6) è
  quella scritta dentro la privata di RP: se `R` è nelle mani sbagliate, il protocollo non lo vede.

**Limiti della catena delle epoche (§3.6), con il server complice.** Il server da solo non fa
adottare una chiave sua; con l'aiuto di chi conosce una `E_n` sì, verso chi non ha in memoria di
che cosa diffidare. Ogni riga dice chi è esposto e chi no.

| # | Chi, con il server | Che cosa ottiene | Chi lo rifiuta | Chi resta esposto |
|---|---|---|---|---|
| L1 | **chiunque conosca `E_n`** (un destinatario attuale o tolto dall'epoca *n*) | firmare un'epoca *n+1*: firmare vale quanto conoscere `E_n`, perché scrive un elenco *n* a una seq più alta con dentro una postazione sua (con `signKey`) e firma con quella. Il controllo della seq già vista (§3.6) non lo ferma | la postazione che ha rinnovato *n → n+1* (firmatari fissati e impegno, §3.6, §4.5); ogni postazione che ha già accettato la *n+1* vera (impegno) | le postazioni che non hanno ancora caricato la *n+1* vera: adottano la biforcazione. La postazione che ha rinnovato si ferma con errore `firma` (è il segnale) |
| L2 | **una postazione tolta dentro un'epoca, senza rinnovo** | firmare su una seq vecchia in cui c'era ancora | chi ha già visto la seq che l'ha tolta (§3.6) | chi non l'ha vista. In DCAM nessuno è tolto dentro un'epoca (si toglie solo col rinnovo, §4.5): il controllo protegge un caso che l'applicazione non produce, e resta come difesa a costo nullo |
| L3 | **un ex destinatario di qualunque epoca**, contro il **recupero 3-4 su un browser che non ha mai usato l'azienda** | l'ancora è solo C_1 e le chiusure `recovery` le può fare chiunque (la pubblica di RP è nell'elenco): da C_1 la catena si verifica con le firme del server, e una biforcazione da un'epoca *k* in cui l'ex destinatario c'era passa | il recupero su un browser che ha già usato l'azienda (parte dagli impegni salvati e dalla seq vista, §5.1) | il recupero su un browser nuovo |
| L4 | **il server da solo**: dichiara revocata una postazione che non lo è (o toglie la sua chiusura) | la postazione dimentica la propria chiave e deve rientrare col codice T o col recupero (§4.2 punto 4) | — sullo stesso browser: seq vista, impegni e firmatari restano (§6.4) e valgono anche su quelle strade | la persona che, per rientrare, passa a un browser nuovo: lì il recupero parte solo da C_1 (L3) |
| L5 | **un rinnovo concorrente di una postazione entrata dopo** l'ultimo caricamento di chi rinnova | — (non è un attacco) | — | la postazione che rinnova riceve un 409, e la *n+1* vera dell'altra è firmata da una postazione che non è fra i firmatari fissati: errore `firma`, si rientra col codice T. Falso allarme raro, a favore della sicurezza |
| L6 | **chiunque abbia una firma valida** | una seconda firma valida dello stesso messaggio (malleabilità ECDSA: `(r, n−s)`); WebCrypto non impone la forma low-S | — | nessuno: la firma non identifica la transizione (il server la conserva per epoca, non per firma) e il messaggio firmato non cambia |

Il protocollo protegge dal server, non da chi è dentro l'azienda: un destinatario attuale conosce
già le chiavi che una biforcazione gli darebbe.

## 2. Chiavi

| Nome | Tipo | Dove nasce | Dove vive | Chi la può aprire |
|---|---|---|---|---|
| **E_n** — chiave d'azienda dell'epoca *n* (n = 1, 2, …) | 32 byte casuali | browser di chi attiva (n=1) o di chi rinnova (n>1) | mai in chiaro fuori dal browser; sul server solo chiusa (§3.3) per ogni destinatario dell'epoca | ogni destinatario dell'elenco dell'epoca *n* |
| **DK_n** — chiave dati | AES-256-GCM | `HKDF(E_n, salt="", info="dcam.riservata.v2.data")` | solo in memoria | — |
| **MK_n** — chiave dell'elenco | AES-256-GCM | `HKDF(E_n, salt="", info="dcam.riservata.v2.manifest")` | solo in memoria | — |
| **P_u** — coppia della persona *u* | ECDH P-256 | browser della persona | pubblica sul server; privata sul server chiusa con KP_u (§3.4) | la persona, con la sua frase |
| **KP_u** — chiave della frase | AES-256-GCM | `Argon2id(NFC(frase), sale_u)` → 32 byte | solo in memoria, il tempo di aprire P_u | — |
| **D_d** — coppia della postazione *d* | ECDH P-256, privata **non estraibile** | browser della postazione | privata in IndexedDB come `CryptoKey` non estraibile; pubblica sul server | solo quel profilo di browser |
| **F_d** — coppia di firma della postazione *d* | ECDSA P-256, privata **non estraibile** | browser della postazione, insieme a D_d | come D_d; la pubblica è anche nell'elenco (`signKey`) | solo quel profilo di browser |
| **C_n** — impegno della chiave d'epoca | 32 byte | `HKDF(E_n, salt="", info="dcam.riservata.v2.commit")` | nella memoria della postazione (accettati) e dentro la privata di RP (C_1, l'ancora) | — (non è segreto, non rivela E_n) |
| **R** — chiave di recupero dell'azienda | 32 byte casuali | browser di chi attiva | solo nel kit stampato, e divisa in 3 parti (§5) | chi ha il kit, o 2 parti su 3 |
| **RP** — coppia di recupero | ECDH P-256 | browser di chi attiva | pubblica sul server; privata sul server chiusa con `HKDF(R, info="dcam.riservata.v2.recovery-kek")`, insieme all'ancora C_1 | chi ricostruisce R |
| **T** — codice di trasferimento | 100 bit casuali (20 caratteri base32 Crockford) | browser di chi autorizza | solo sullo schermo di chi autorizza e nelle mani di chi lo digita | — |

**La frase personale non è la password di accesso.** La password di login arriva al server; se la
chiave personale ne derivasse, il server avrebbe ciò che serve per calcolarla. La frase è
separata e si chiede solo su una postazione nuova, al cambio frase e nel recupero: l'uso
quotidiano passa dalla chiave della postazione.

### 2.1 Parametri

- **Argon2id:** `opslimit = 3`, `memlimit = 64 MiB` (67108864 byte), parallelismo 1 (libsodium),
  uscita 32 byte, sale di 16 byte casuali per persona. La frase si normalizza in **NFC** prima
  della codifica UTF-8. I parametri si salvano accanto al testo chiuso (§3.4), così si possono
  cambiare senza rompere i record vecchi. Arrivano dal server, quindi chi apre accetta solo
  `ops` intero in [1, 10], `mem` intero in [8 MiB, 256 MiB] e sale di 16 byte (errore `formato`
  altrimenti): il server non può imporre un costo enorme al browser. Sono anche nell'AAD (§3.4). Tempi misurati su un portatile Ryzen 7 5825U: Chromium
  0,5-0,6 s, WebKit 0,6-0,7 s, Firefox 2,4-3,5 s, Node 0,5 s.
- **Frase:** minimo 12 caratteri (dopo NFC).
- **AES-256-GCM:** nonce di 12 byte da `getRandomValues`, tag di 16 byte. Limite di 2^32
  cifrature per chiave con nonce casuale (NIST SP 800-38D): chi integra conta le cifrature per
  epoca e chiede un rinnovo prima del limite.

## 3. Formati

Tutti gli interi sono **big-endian senza segno**. Le stringhe sono **UTF-8**. Le codifiche base64
sono **base64url senza riempimento** (RFC 4648 §5).

### 3.1 AAD canonico

```
AAD(campi…) = "dcam.riservata.v2" || 0x00 || campo_1 || 0x00 || campo_2 || … || campo_k
```

Nessun campo può contenere il byte 0x00 (la funzione rifiuta con errore `formato`). I numeri
devono essere interi sicuri non negativi e si scrivono in decimale senza zeri iniziali.

Codice: `aad()` in `src/formato.ts`.

### 3.2 Busta di un oggetto — `DCR2`

```
offset  byte  campo
0       4     magic "DCR2"
4       1     alg = 0x01 (AES-256-GCM con DK_epoch)
5       4     epoch (uint32)
9       12    nonce
21      …     testo cifrato || tag (16)
```

- AAD = `AAD("obj", orgId, kind, objectId, rev, part, epoch)` con `part` ∈ `meta` | `thumb` | `body`.
- Testo in chiaro = `codec (1 byte) || dati`, con `codec` 0x00 = grezzo, 0x01 = **deflate con
  intestazione zlib (RFC 1950)**, cioè `CompressionStream('deflate')`. Il codec è dentro la
  cifratura, quindi autenticato. La parte `body` si comprime; `meta` e `thumb` restano grezze.
- La decompressione si ferma oltre **256 MiB** in uscita (errore `formato`), contando i pezzi
  mentre escono: una busta di pochi KB non può gonfiarsi senza limite. Solo chi ha `E_epoch`
  può costruire una busta che superi l'apertura GCM, ma il tetto vale per tutti.
- `dati` = JSON UTF-8 per `meta` e `body`; byte PNG per `thumb`.
- L'epoca è **sia nell'intestazione sia nell'AAD**: l'intestazione dice quale chiave usare, l'AAD
  impedisce di mentire su quale chiave sia stata usata.
- Un `alg` diverso da 0x01 o un `codec` sconosciuto si rifiutano con errore `formato`; un'epoca di
  cui non si ha la chiave con errore `epoca`.

Una **versione** di un oggetto è la terna `(meta, thumb?, body?)` con lo stesso
`(kind, objectId, rev)`.

Codice: `chiudiParte`/`apriParte`/`epocaDi` in `src/oggetto.ts`.

### 3.3 Chiusura di una chiave per un destinatario (wrap)

```
wrap(chiave32, pkDestinatario, ctx) =
  HPKE.Seal(mode_base, pkR = pkDestinatario, info = AAD("wrap", ctx…), aad = "", pt = chiave32)
  → enc (65 byte, punto P-256 non compresso) || ct (32 + 16 byte) = 113 byte
```

- `ctx` per una chiave d'epoca: `("epoch", orgId, epoch, recipientKind, recipientId)` con
  `recipientKind` ∈ `person` | `device` | `recovery`.
- L'`info` HPKE lega la chiusura a destinatario ed epoca: il server non può consegnare a una
  postazione la chiusura destinata a un'altra, né far passare `E_3` per `E_4`.
- Una chiusura di lunghezza diversa da 113 byte si rifiuta (errore `formato`).
- **Una chiusura non dice chi l'ha fatta** (HPKE modo base): una chiusura che si apre prova solo
  che è destinata a questa chiave. Che la chiave d'epoca sia quella vera lo dice la §3.6.

Codice: `chiudiPer`/`apriPer` in `src/chiavi.ts`.

### 3.4 Chiusura simmetrica — `DCS2`

```
seal(K, pt, aad) = "DCS2" || nonce (12) || AES-256-GCM(K, nonce, pt, aad)
```

Usata per:

| Cosa | K | aad |
|---|---|---|
| privata di P_u (PKCS#8) | KP_u | `AAD("person", orgId, userId, pubKey, alg, ops, mem, salt)` |
| C_1 (32 byte) ‖ privata di RP (PKCS#8) | `HKDF(R, salt="", info="dcam.riservata.v2.recovery-kek")` | `AAD("recovery", orgId, pubKeyRP)` |
| pacchetto di trasferimento (§4.3) | KT | `AAD("transfer", orgId, transferId, forUserId)` |

Il record della persona sul server:
`{pubKey, sealedPriv, kdf: {alg: "argon2id13", ops: 3, mem: 67108864, salt}}` (base64url).
`pubKey` e i parametri sono nell'AAD: il server non può accoppiare la privata a un'altra pubblica.
Lo stesso per RP: `pubKeyRP` (base64url) è nell'AAD.

Codice: `seal`/`unseal` in `src/formato.ts`; `creaPersona`/`apriPersona`,
`creaRecupero`/`apriRecupero` in `src/chiavi.ts`.

### 3.5 Elenco dei destinatari — `DCM2`

Il server non può aggiungere un destinatario: l'elenco è cifrato e autenticato con MK_n. Chi
chiude una chiave per qualcuno lo fa **solo** verso le chiavi pubbliche dell'elenco autenticato.

```
elenco (JSON prima della cifratura) = {
  "v": 2, "orgId": "...", "epoch": n, "seq": k,          // seq: 1, 2, … dentro l'epoca
  "recovery": { "pubKey": "<b64url>" },
  "recipients": [
    { "kind": "person"|"device", "id": "...", "userId": "...", "label"?: "...",
      "pubKey": "<b64url>", "signKey"?: "<b64url>",        // signKey: solo device (F_d)
      "addedBy": "...", "addedAt": <ms> }
  ]
}
busta = "DCM2" || nonce (12) || AES-256-GCM(MK_n, nonce, json, AAD("manifest", orgId, n, k))
```

- Chi apre dichiara `(orgId, epoch, seq)` attesi: entrano nell'AAD, e dopo l'apertura il browser
  rifiuta (errore `elenco`) un contenuto con `v`, `orgId`, `epoch` o `seq` diversi.
- Il server accetta una nuova versione dell'elenco solo con `seq = ultimo + 1`.
- L'elenco è autenticato con una chiave **simmetrica**: chiunque abbia `E_n` (cioè ogni
  destinatario dell'epoca) può scrivere un elenco valido. Protegge dal server, non da un
  destinatario.

- Dentro un'epoca (`seq > 1`) l'elenco resta autenticato solo con MK_n: il server, senza `E_n`, non
  scrive una versione valida. Il passaggio a un'epoca **nuova** è la §3.6.

Codice: `chiudiElenco`/`apriElenco`/`conAggiunti`/`perRinnovo`/`chiusurePerEpoca` in `src/elenco.ts`.

### 3.6 Epoche firmate

Una chiave `E_{n+1}` vale solo se una **postazione dell'elenco n** l'ha firmata. Il server ha tutte
le pubbliche e può chiudere per una postazione una chiave che conosce; non ha nessuna privata di
firma né `E_n`, quindi non può né firmare né scrivere un elenco *n* con una postazione sua. Chi
conosce `E_n` sì: con lui il server può firmare (§1, L1). Le difese contro questo caso stanno
nella **memoria della postazione** qui sotto.

```
C_n = HKDF(E_n, salt="", info="dcam.riservata.v2.commit")             // 32 byte
m   = AAD("transition", orgId, n+1, prevSeq, b64url(C_{n+1}),
          b64url(SHA-256(busta DCM2 dell'elenco n alla seq prevSeq)), signerId)
sig = ECDSA-P256-SHA256(F_signer, m)                                    // 64 byte, r ‖ s
transizione n+1 = { epoch: n+1, prevSeq, prevBlob: busta dell'elenco n a prevSeq, signerId, sig }
```

Chi verifica la transizione `n+1`, avendo già accettato `E_n`:

1. apre `prevBlob` con MK_n dichiarando `(orgId, n, prevSeq)` (errori `apertura`/`elenco`);
2. cerca una voce `device` con `id = signerId` e `signKey`; se manca, errore `firma`;
3. verifica `sig` su `m` con `signKey`, calcolando `C_{n+1}` dalla chiave candidata; se non
   torna, errore `firma`.

**Accettare le chiavi** (`verificaChiavi`): la postazione tiene gli impegni già accettati
(epoca → C). Per ogni chiave ricevuta, in ordine di epoca: se l'epoca ha già un impegno, la
chiave deve dare lo stesso (vale anche per le epoche **vecchie**: altrimenti il server, chiudendo
una chiave sua per un'epoca passata, farebbe aprire oggetti falsi); se è nuova, deve avere la
precedente accettata e una transizione che si verifica. Senza nessun impegno di partenza non si
accetta niente.

**La memoria della postazione** (`verificaChiavi(…, { visto, firmatari })`), persistente accanto
agli impegni e usata su tutte le strade da cui arrivano chiavi (caricamento, codice T, recupero),
quando il browser ha già usato l'azienda:

- **seq vista** (`visto`): se la postazione ha già aperto l'elenco dell'epoca *n* alla seq *s*, una
  transizione `n+1` firmata su una seq minore di *s* si rifiuta (errore `firma`). Ferma una
  postazione tolta dentro un'epoca che firma su una seq vecchia; NON ferma chi conosce `E_n`, che
  scrive un elenco a una seq più alta (§1, L1-L2);
- **firmatari fissati** (`firmatari`: epoca → coppie id della postazione → `signKey`): chi rinnova
  *n → n+1* fissa, PRIMA di inviare, le postazioni con `signKey` dell'elenco *n+1* che ha costruito
  (quelle dell'elenco *n* da cui parte meno quelle che toglie). Conta la coppia, non l'id: chi
  conosce `E_n` può scrivere un elenco *n* con l'id di una postazione rimasta e una `signKey` sua.
  Una `n+1` firmata da un'altra postazione — la tolta, una coniata, o un id noto con una chiave
  diversa — si rifiuta (errore `firma`). Vale
  anche se la risposta del server si perde, o se il server risponde «un altro ha rinnovato» (409):
  la *n+1* vera di un altro amministratore, firmata da una postazione rimasta, passa;
- **impegno di chi rinnova**: dopo la risposta positiva del server, chi ha rinnovato salva
  l'impegno di `E_{n+1}` fra quelli accettati; da lì nessun'altra *n+1* passa, chiunque la firmi.
  Non lo salva prima di inviare: se il rinnovo non arrivasse e un altro amministratore rinnovasse,
  la postazione resterebbe fuori per sempre (la finestra è coperta dai firmatari fissati).

Chi applica il protocollo lato server accetta la firma solo sull'ultima seq dell'epoca corrente.

**L'ancora** (il primo impegno accettato) non viene mai dal server:

| Chi | Ancora |
|---|---|
| la postazione che attiva | genera `E_1`, ne calcola C_1 |
| una postazione nuova (§4.3) | gli `E_n` del pacchetto chiuso con T (il server non conosce T): ne calcola gli impegni |
| il recupero 3-4 (§5) | C_1, scritto dentro la privata di RP chiusa con R, più gli impegni che quel browser ha già accettato (§1, L3) |

Il server conserva le transizioni accanto all'elenco *n+1* e le consegna con le chiusure.

Codice: `impegno`/`firmaTransizione`/`verificaTransizione`/`verificaChiavi`/`generaCoppiaFirma`
in `src/firma.ts`.

## 4. Operazioni

Le operazioni combinano le primitive della §3. La parte di rete e di archiviazione è
dell'applicazione che integra il pacchetto, non di questo repository.

### 4.1 Attivazione

1. Il browser genera `E_1`, `R`, `RP`, `P_owner` (chiede la frase), `D_d` e `F_d` della
   postazione; chiude con R la privata di RP insieme a C_1 (§3.4, §3.6).
2. Costruisce l'elenco `epoch=1, seq=1`: persona del titolare, postazione (con `signKey`), recupero.
3. Chiude `E_1` per ognuno dei tre destinatari (§3.3).
4. Divide `R` in 3 parti con Shamir 2-di-3 → `A` (kit), `B` (DCAM), `C` (terza persona).
5. Chiude `B` per la **chiave di custodia** di DCAM legandola alla pubblica di RP (§5.2) → `B'`.
6. Fa stampare il **kit**: `R` in 13 gruppi da 4 caratteri base32 Crockford, la parte `A`, e la
   parte `C` da consegnare alla terza persona. Il kit si genera nel browser e non si invia.
7. Invia al server: elenco, chiusure, record persona, postazione, pubblica e privata chiusa di RP,
   `B'`.

### 4.2 Uso quotidiano su una postazione autorizzata

1. Il browser legge da IndexedDB l'id della postazione e la privata di `D_d` (non estraibile).
2. Scarica le chiusure di tutte le epoche per quella postazione e l'elenco corrente.
3. Apre le chiusure con `D_d`, **accetta le chiavi con la §3.6** (impegni già accettati +
   transizioni nuove), verifica l'elenco con `MK` dell'ultima epoca, tiene le `E_n` solo in
   memoria e gli impegni accettati nella memoria persistente della postazione.
4. Se la postazione non è nell'elenco o la chiusura manca, la postazione è stata revocata.

### 4.3 Postazione nuova e recupero di livello 1-2

Chi autorizza (una postazione già autorizzata della stessa persona, o di un amministratore):

1. genera `T` (20 simboli casuali base32 Crockford = 100 bit) e un `transferId`;
2. `KT = HKDF(UTF-8(normalizza(T)), salt = UTF-8(transferId), info = "dcam.riservata.v2.transfer")`,
   dove `normalizza` porta in maiuscolo, toglie spazi e trattini e mappa `O→0`, `I/L→1`;
3. pacchetto = JSON `{orgId, forUserId, epochs: {n: E_n …}, manifest: {epoch, seq, blob}}`;
4. invia `seal(KT, pacchetto, AAD("transfer", orgId, transferId, forUserId))` con scadenza breve
   e una sola lettura;
5. mostra `T` a schermo.

La postazione nuova digita `T`, apre il pacchetto (che deve dichiarare lo stesso `orgId` e
`forUserId`, altrimenti errore `apertura`), prende come ancora gli impegni di **tutti** gli `E_n`
del pacchetto, controlla con la §3.6 le chiavi che il server le consegna dopo, genera `D_d` e
`F_d`, se serve crea `P_u` con una frase nuova, si aggiunge all'elenco (`seq + 1`) e chiude le
`E_n` per sé.

In DCAM il `transferId` si ricava da `T` (`SHA-256("dcam.riservata.v2.transfer-id:" || T)`, primi
16 byte, base64url): chi entra digita solo `T`, e il server continua a non conoscerlo.

Il codice va da chi autorizza a chi entra: il server non conosce `T` e non può indovinare 100 bit
nella vita breve del pacchetto; non c'è una chiave pubblica da confrontare a occhio.

### 4.4 Persona nuova

È la §4.3 con chi autorizza = un amministratore e `forUserId` = la persona invitata.

### 4.5 Rinnovo (uscita di una persona, revoca di una postazione, sospetto)

1. L'amministratore genera `E_{n+1}`.
2. Costruisce l'elenco `epoch = n+1, seq = 1` = elenco corrente **meno** la persona uscita e
   tutte le sue postazioni (o meno la postazione revocata).
3. Chiude `E_{n+1}` per ogni destinatario rimasto **e per RP** (la pubblica di recupero è
   nell'elenco: il kit non serve per rinnovare).
4. Firma la transizione `n+1` con la `F_d` della postazione da cui rinnova, sull'elenco *n* da cui
   è partito (§3.6).
5. Fissa nella memoria della postazione i firmatari possibili di *n+1* (§3.6).
6. Invia tutto in una richiesta atomica; alla risposta positiva salva l'impegno di `E_{n+1}`.

Le postazioni della persona uscita non sono nell'elenco *n+1*: non firmano l'epoca *n+2*. Con il
server possono ancora firmare una *n+1* diversa al posto di questa: la rifiutano chi ha rinnovato e
chi ha già accettato la vera, non le altre (§1, L1).

Dopo il rinnovo il server rifiuta le scritture con epoca inferiore alla corrente. La persona
uscita conosce le chiavi fino all'epoca *n*: i dati scritti prima del rinnovo restano leggibili
per lei se ne aveva copia (limite della §1).

## 5. Recupero

### 5.1 La scala

| Livello | Cosa serve | Meccanismo |
|---|---|---|
| 1 | un'altra postazione della persona | §4.3 |
| 2 | un amministratore | §4.3 con chi autorizza = amministratore |
| 3 | il kit (`R`) | `R` → apre la privata di RP e l'ancora C_1 → apre le chiusure `recovery` di tutte le epoche e le accetta con la §3.6 partendo da C_1 e dagli impegni che il browser ha già accettato (un C_1 diverso da quello salvato: errore `firma`) → nuova postazione e nuova `P_u`. Su un browser nuovo l'ancora è solo C_1 (§1, L3). Dopo l'uso si propone un kit nuovo |
| 4 | 2 parti su 3 fra `A` (kit), `B` (DCAM), `C` (terza persona) | si ricostruisce `R` nel browser, poi come il livello 3. Dopo l'uso il kit nuovo è obbligatorio |

Le parti Shamir sono quelle della libreria `shamir-secret-sharing` (l'ultimo byte di ogni parte è
la sua coordinata x). Due parti con la stessa coordinata si rifiutano prima di combinarle (errore
`parti`); il risultato deve essere di 32 byte.

### 5.2 La parte di DCAM (custodia)

- `B` arriva al server già chiusa per la **chiave di custodia** di DCAM:
  `HPKE.Seal(mode_base, pkCustodia, info = AAD("custodia", orgId, pubKeyRP), aad = "", pt = B)`,
  stesso formato della §3.3 ma di **114 byte** (la parte è di 33 byte: 32 + la coordinata x).
  `pubKeyRP` (base64url) lega `B'` al suo kit: la parte di un kit vecchio non passa per quella del
  nuovo. Una chiusura di lunghezza diversa si rifiuta (errore `formato`). La privata di custodia è generata fuori linea e non è in
  linea; la pubblica è in `src/custodia.ts`. Né un furto del database né un operatore con accesso
  al server hanno `B` in mano; e `B` da sola non ricostruisce `R`.
- ⚠️ **In questa versione `src/custodia.ts` contiene una chiave di SVILUPPO dichiarata**
  (`CUSTODIA_SVILUPPO = true`, privata distrutta). Chi integra deve rifiutare l'attivazione in
  produzione finché vale `true`. La chiave definitiva sostituirà questo valore in una versione
  successiva del pacchetto.
- La consegna di `B` al cliente avviene fuori linea, dopo una verifica d'identità.

## 6. Sincronizzazione, conflitti, ricerca

Queste regole sono dell'applicazione e del server; il pacchetto fornisce i formati.

### 6.1 Numerazione

Ogni oggetto ha revisioni `1, 2, 3, …` senza buchi. Il server accetta solo `rev = head + 1` e non
riscrive mai una versione esistente.

### 6.2 Conflitti

Al conflitto il browser scarica la versione più recente, la apre e propone: tieni la tua, tieni
la sua, salva come copia. Nessuna fusione.

### 6.3 Catalogo e ricerca

Il server consegna le parti `meta` cifrate; il browser le apre in memoria e costruisce lì
l'indice (ricerca, filtri, ordinamento). L'unicità dei nomi si controlla nel browser: due
salvataggi simultanei con lo stesso nome da due postazioni possono passare entrambi.

### 6.4 Rollback

Il browser ricorda, per azienda, l'epoca più alta vista, il `seq` più alto dell'elenco per
quell'epoca, gli impegni delle epoche accettate (§3.6) e, per oggetto, la `rev` più alta vista. Se il server consegna qualcosa di più vecchio,
il browser si ferma con un errore. Una postazione nuova non ha memoria: lì il rollback non si vede.

## 7. Cosa resta in chiaro sul server

| Dato | Perché serve | Cosa rivela |
|---|---|---|
| account, email, nome della persona, appartenenza, ruoli, licenze, inviti | accesso | chi lavora in quale azienda |
| nome dell'azienda | fatturazione, interfaccia | — |
| stato della cifratura, epoca corrente, date di attivazione e rinnovo | protocollo | quando qualcuno è uscito |
| per epoca ≥ 2: la transizione (§3.6) con `signerId` | protocollo | quale postazione ha rinnovato |
| per postazione: id, persona, etichetta scelta dall'utente, chiave pubblica (e di firma, dentro l'elenco cifrato), date | elenco postazioni, revoca | quante postazioni e di chi |
| per persona: chiave pubblica, privata chiusa, parametri Argon2id | recupero da postazione nuova | — |
| per versione: `kind`, `objectId` (UUID casuale), `rev`, cursore, epoca, autore, data, cancellazione, **dimensione** delle buste | numerazione, conflitti, cursore | quanti oggetti, quando e da chi sono salvati, quanto sono grandi |
| registro di audit | sicurezza | azione e id, mai nomi |
| indirizzi IP, orari di accesso | log | — |

**Cifrato:** tutto il contenuto degli oggetti (nomi, materiali, spessori, commesse, clienti,
note, campi personalizzati, miniature, disegni, entità, dati dei nesting, note di revisione).

## 8. Integrazione

Fuori da questo pacchetto, e quindi fuori da questo documento: le rotte del server, l'archivio
delle buste, l'interfaccia, la conservazione delle chiavi in IndexedDB, la migrazione dei dati
esistenti. Il pacchetto non fa rete e non salva niente.

## 9. Versioni del protocollo

Tutto ciò che è qui è **v2**: magic `DCR2`/`DCS2`/`DCM2`, prefisso AAD `dcam.riservata.v2`, info
HKDF `dcam.riservata.v2.*`, elenco con `"v": 2`. I vettori di `vettori/v2.json` non si rigenerano:
restano la prova che le buste v2 si aprono. Un cambiamento incompatibile crea una v3 con magic e
prefisso nuovi.

**La v1 non si apre con questo codice.** La v1 (pacchetto 0.1.0) non è mai stata pubblicata e non
protegge dalla scelta della chiave d'epoca da parte del server (§3.6): la v2 la sostituisce. Al
momento del cambio nessuna azienda aveva dati v1 in produzione. I vettori v1 restano nella storia
del repository.
