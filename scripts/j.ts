import * as jose from 'jose'

function hexStringToUint8Array(hexString) {
    return new Uint8Array(
      hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );
  }
  

// https://github.com/panva/jose/blob/main/docs/functions/key_generate_secret.generateSecret.md
// const secret = await jose.generateSecret('HS256') // 256 bit (32 byte) secret
// const secret = await jose.generateSecret('HS256', { extractable: true }) // 256 bit (32 byte) secret
// const secret = await jose.generateSecret('A256GCM', { extractable: true }) // 256 bit (32 byte) secret
// console.log('secret: %o', secret)
// console.log('secret.toString():', secret.toString())
// console.log('secret.symmetricKeySize():', secret.symmetricKeySize) // KeyObject in node

// https://www.grc.com/passwords.htm
// 64 hex characters  =  256 binary bits
const hex64 = "8089BECBD6DB20F96EE78A6EE81B7076E1A319D5AC7DE27E476E81BF7BF545D4"
const secret = hexStringToUint8Array(hex64);

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
