// src/errori.ts
export type CodiceErrore =
  | 'formato'
  | 'apertura'
  | 'elenco'
  | 'rollback'
  | 'epoca'
  | 'frase'
  | 'parti'
  | 'postazione';

/** Ogni fallimento del protocollo ha un codice: l'interfaccia decide la frase, i test il codice. */
export class ErroreRiservata extends Error {
  constructor(
    readonly codice: CodiceErrore,
    messaggio: string
  ) {
    super(messaggio);
    this.name = 'ErroreRiservata';
  }
}
