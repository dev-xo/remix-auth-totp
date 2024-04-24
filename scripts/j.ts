import * as jose from 'jose'
import { generateTOTP, verifyTOTP } from '@epic-web/totp'
import { generateSecret } from '../src/utils'

// pnpm tsx scripts/j.ts

// export const TOTP_GENERATION_DEFAULTS: Required<TOTPGenerationOptions> = {
//   secret: base32.encode(crypto.randomBytes(10)).toString() as string,
//   algorithm: 'SHA1',
//   charSet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
//   digits: 6,
//   period: 60,
//   maxAttempts: 3,
// }

const totpOptions = {
  //   algorithm: 'SHA1',
  algorithm: 'SHA256',
  charSet: 'abcdefghijklmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ123456789', // no O or 0
  digits: 6,
  period: 60,
}

const { otp: code, ...totpPayload } = generateTOTP({
  ...totpOptions,
  secret: generateSecret(),
})

console.log('generateTOTP:', { code, totpPayload })

// https://www.grc.com/passwords.htm
// 64 hex characters  =  256 binary bits
const secret64HexChars =
  'b2FE35059924CDBF5B52A84765B8B010F5291993A9BC39410139D4F511006034'
if (!/^[0-9a-fA-F]{64}$/.test(secret64HexChars)) {
  throw new Error('secret64HexChars must be a string with 64 hex characters')
}
const secret = Buffer.from(secret64HexChars, 'hex')

// https://github.com/panva/jose/blob/main/docs/classes/jwe_compact_encrypt.CompactEncrypt.md
const jwe = await new jose.CompactEncrypt(
  new TextEncoder().encode(JSON.stringify(totpPayload)),
)
  .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
  .encrypt(secret)
console.log('jwe:', jwe)

// https://github.com/panva/jose/blob/main/docs/functions/jwe_compact_decrypt.compactDecrypt.md
const { plaintext, protectedHeader } = await jose.compactDecrypt(jwe, secret)
console.log('cpompactDecrypt:', {
  protectedHeader,
  plaintext: new TextDecoder().decode(plaintext),
})

const totpPayloadDecrypted = JSON.parse(new TextDecoder().decode(plaintext))
// validate payload
console.log('totpPayloadDecrypted:', totpPayloadDecrypted)

const verifyResult = verifyTOTP({ ...totpPayloadDecrypted, otp: code })
console.log('verifyTOTP:', verifyResult)
