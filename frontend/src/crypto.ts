export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      res = (res * base) % mod;
    }
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return res;
}

export function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) {
    const temp = b;
    b = a % b;
    a = temp;
  }
  return a;
}

export function modInverse(a: bigint, m: bigint): bigint {
  let m0 = m;
  let y = 0n;
  let x = 1n;

  if (m === 1n) return 0n;

  while (a > 1n) {
    let q = a / m;
    let t = m;

    m = a % m;
    a = t;
    t = y;

    y = x - q * y;
    x = t;
  }

  if (x < 0n) x += m0;

  return x;
}

export function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let res = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    res = (res << 8n) | BigInt(bytes[i]);
  }
  return res;
}

export function bigIntToBytesLE(value: bigint, minLength = 0): Uint8Array {
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.push(Number(value & 255n));
    value >>= 8n;
  }
  while (bytes.length < minLength) {
    bytes.push(0);
  }
  return new Uint8Array(bytes);
}

export function randomBigInt(max: bigint): bigint {
  const hex = max.toString(16);
  const bytes = Math.ceil(hex.length / 2);
  
  while (true) {
    const randomBytes = new Uint8Array(bytes);
    crypto.getRandomValues(randomBytes);
    
    let r = 0n;
    for (let i = randomBytes.length - 1; i >= 0; i--) {
        r = (r << 8n) | BigInt(randomBytes[i]);
    }

    if (r > 0n && r < max) {
      return r;
    }
  }
}

export function base64ToBytes(base64: string): Uint8Array {
  const binString = atob(base64);
  const bytes = new Uint8Array(binString.length);
  for (let i = 0; i < binString.length; i++) {
    bytes[i] = binString.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  const chars = [];
  for (let i = 0; i < bytes.length; i++) {
    chars.push(String.fromCharCode(bytes[i]));
  }
  return btoa(chars.join(""));
}
