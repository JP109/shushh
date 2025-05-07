// derive a 32-byte key + 32-byte IV from sharedSecret (BigInt → Uint8Array)
export async function deriveAESKeyAndIV(sharedSecretBigInt) {
  // convert to bytes
  const hex = sharedSecretBigInt.toString(16).padStart(512, "0");
  const sharedBytes = Uint8Array.from(
    hex.match(/.{2}/g).map((b) => parseInt(b, 16))
  );
  // SHA-512
  const hash = await crypto.subtle.digest("SHA-512", sharedBytes);
  const h = new Uint8Array(hash);
  return {
    key: h.slice(0, 32),
    iv: h.slice(32, 64),
  };
}
