import * as jose from 'jose'

// https://github.com/panva/jose/blob/main/docs/functions/key_generate_secret.generateSecret.md
const secret = await jose.generateSecret('HS256') // 256 bit (32 byte) secret
console.log('secret: %o', secret)

// https://github.com/panva/jose/blob/main/docs/classes/jwe_compact_encrypt.CompactEncrypt.md
const jwe = await new jose.CompactEncrypt(
  new TextEncoder().encode('It’s a dangerous business, Frodo, going out your door.'),
)
  .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
  .encrypt(secret)
console.log(jwe)

// https://github.com/panva/jose/blob/main/docs/functions/jwe_compact_decrypt.compactDecrypt.md
const { plaintext, protectedHeader } = await jose.compactDecrypt(jwe, secret)

console.log(protectedHeader)
console.log(new TextDecoder().decode(plaintext))
