import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto'

/**
 * SCRAM-SHA-256 as implemented by Huawei LTE routers (password_type 3/4).
 *
 * Huawei deviates from RFC 5802 in the argument order of the two HMACs, so the
 * exact ordering here matters: get it wrong and the router rejects the proof.
 * The scheme is reproduced faithfully from the public huawei-lte-api project.
 *
 * No password ever leaves the local machine: this computes the proof that the
 * router's own web UI would compute, so the plaintext password is only ever
 * used to derive a one-time proof against a server-supplied salt and nonce.
 */

export function clientNonce(): string {
  return randomBytes(32).toString('hex')
}

/**
 * Derives the SCRAM client proof.
 *
 * @param password   the admin password, used only to derive the proof
 * @param salt       hex salt from the challenge response
 * @param iterations PBKDF2 iteration count from the challenge response
 */
export function scramClientProof(
  clientnonce: string,
  servernonce: string,
  password: string,
  salt: string,
  iterations: number
): string {
  const authMsg = `${clientnonce},${servernonce},${servernonce}`
  const saltedPassword = pbkdf2Sync(password, Buffer.from(salt, 'hex'), iterations, 32, 'sha256')

  // Huawei order: key = literal "Client Key", message = salted password.
  const clientKey = createHmac('sha256', 'Client Key').update(saltedPassword).digest()
  const storedKey = createHash('sha256').update(clientKey).digest()
  // Huawei order: key = auth message, message = stored key.
  const signature = createHmac('sha256', authMsg).update(storedKey).digest()

  const proof = Buffer.alloc(clientKey.length)
  for (let i = 0; i < clientKey.length; i++) proof[i] = clientKey[i] ^ signature[i]
  return proof.toString('hex')
}

/**
 * Simple hashed login used by older firmwares (password_type < 3):
 *   base64( SHA256( name + base64(SHA256(password)) + token ) )
 */
export function hashedPassword(username: string, password: string, token: string): string {
  const inner = createHash('sha256').update(password).digest('base64')
  return createHash('sha256').update(`${username}${inner}${token}`).digest('base64')
}
