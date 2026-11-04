// src/custodia.ts
// Chiave PUBBLICA di custodia DCAM (ECDH P-256, punto non compresso) (protocollo §5.2). La privata non è in
// questo repository: esiste solo su carta (cerimonia del 2026-11-04, impronta a14a2a9a5d9ec116 = le prime
// 16 cifre esadecimali di sha256 della stringa base64url qui sotto). È la chiave definitiva:
// CUSTODIA_SVILUPPO è false.
import { da64 } from './bytes';
export const CUSTODIA_SVILUPPO = false;
export const CUSTODIA_PUBBLICA: Uint8Array = da64(
  'BOKDe9r4eiVALJI96w7J1fKR60kYDNXx2NT7bh5I50qMbqxz7hX1fWLJ5ALRf8jvQcQRdJrvl6cSV0wDIGXn4u4'
);
