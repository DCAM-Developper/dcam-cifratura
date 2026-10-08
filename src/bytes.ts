// src/bytes.ts
export function concatena(...parti: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parti.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parti) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function casuali(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** ArrayBuffer ESATTO della vista (un subarray condivide il buffer intero). */
export function ab(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

export function a64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function da64(s: string): Uint8Array {
  const norm = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(norm + '='.repeat((4 - (norm.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
