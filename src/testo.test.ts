// @vitest-environment node
// src/testo.test.ts
import { describe, expect, test } from 'vitest';
import { aBase32, daBase32, aGruppi } from './testo';
import { ErroreRiservata } from './errori';

describe('Crockford base32', () => {
  test('32 byte → 52 caratteri, ritorno esatto', () => {
    const b = crypto.getRandomValues(new Uint8Array(32));
    const s = aBase32(b);
    expect(s).toHaveLength(52);
    expect(daBase32(s, 32)).toEqual(b);
  });
  test('100 bit del codice di trasferimento = 20 caratteri', () => {
    // 13 byte = 104 bit → 21 caratteri; il codice usa 100 bit esatti: 20 caratteri,
    // generati come 20 simboli casuali (simboliCasuali), non da byte.
    expect(aBase32(new Uint8Array(13))).toHaveLength(21);
  });
  test('lettura tollerante: minuscole, O→0, I/L→1, spazi e trattini ignorati', () => {
    const b = crypto.getRandomValues(new Uint8Array(32));
    const s = aBase32(b);
    const sporco = aGruppi(s).toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l');
    expect(daBase32(sporco, 32)).toEqual(b);
  });
  test('carattere estraneo (U) o lunghezza sbagliata → ErroreRiservata «formato»', () => {
    expect(() => daBase32('U'.repeat(52), 32)).toThrow(ErroreRiservata);
    expect(() => daBase32('U'.repeat(52), 32)).toThrow(
      expect.objectContaining({ codice: 'formato' })
    );
    expect(() => daBase32('0'.repeat(10), 32)).toThrow(
      expect.objectContaining({ codice: 'formato' })
    );
  });
  test('gruppi da 4 separati da trattino', () => {
    expect(aGruppi('ABCDEFGHJK')).toBe('ABCD-EFGH-JK');
  });
});
