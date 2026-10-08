// src/custodia.ts
// Chiave PUBBLICA di custodia DCAM (ECDH P-256, punto non compresso) (protocollo §5.2). La privata non è in
// questo repository. Il valore qui sotto è una chiave di SVILUPPO dichiarata (la sua privata è stata distrutta):
// chi integra il pacchetto deve rifiutare l'attivazione in produzione finché CUSTODIA_SVILUPPO è true.
import { da64 } from './bytes';
export const CUSTODIA_SVILUPPO = true;
export const CUSTODIA_PUBBLICA: Uint8Array = da64(
  'BFym4Q3bi4Yuz64p6dVnXDibfbuHecdvzTvDr_Wt7yhFcVGoEDCOHDKHD1-Wfz1XlSY6K3_ziZzn3_nzp5MzcsM'
);
