import type { TOTPData, TOTPCookieData } from './index.js'
import base32Encode from 'base32-encode'

/**
 * TOTP Generation.
 */
export function generateSecret() {
  const randomBytes = new Uint8Array(32)
  crypto.getRandomValues(randomBytes)
  return base32Encode(randomBytes, 'RFC4648').toString() as string
}

// https://github.com/sindresorhus/uint8array-extras/blob/main/index.js#L222
const hexToDecimalLookupTable = {
  0: 0,
  1: 1,
  2: 2,
  3: 3,
  4: 4,
  5: 5,
  6: 6,
  7: 7,
  8: 8,
  9: 9,
  a: 10,
  b: 11,
  c: 12,
  d: 13,
  e: 14,
  f: 15,
  A: 10,
  B: 11,
  C: 12,
  D: 13,
  E: 14,
  F: 15,
}
function hexToUint8Array(hexString: string) {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid Hex string length.')
  }

  const resultLength = hexString.length / 2
  const bytes = new Uint8Array(resultLength)

  for (let index = 0; index < resultLength; index++) {
    const highNibble =
      hexToDecimalLookupTable[
        hexString[index * 2] as keyof typeof hexToDecimalLookupTable
      ]
    const lowNibble =
      hexToDecimalLookupTable[
        hexString[index * 2 + 1] as keyof typeof hexToDecimalLookupTable
      ]

    if (highNibble === undefined || lowNibble === undefined) {
      throw new Error(`Invalid Hex character encountered at position ${index * 2}`)
    }

    bytes[index] = (highNibble << 4) | lowNibble
  }

  return bytes
}

/**
 * Redirect.
 */
export function redirect(url: string, init: ResponseInit | number = 302) {
  let responseInit = init

  if (typeof responseInit === 'number') {
    responseInit = { status: responseInit }
  } else if (typeof responseInit.status === 'undefined') {
    responseInit.status = 302
  }

  const headers = new Headers(responseInit.headers)
  headers.set('Location', url)

  return new Response(null, { ...responseInit, headers })
}

/**
 * Miscellaneous.
 */
export function asJweKey(secret: string) {
  if (!/^[0-9a-fA-F]{64}$/.test(secret)) {
    throw new Error('Secret must be a string with 64 hex characters.')
  }
  return hexToUint8Array(secret)
}

export function coerceToOptionalString(value: unknown) {
  if (typeof value !== 'string' && value !== undefined) {
    throw new Error('Value must be a string or undefined.')
  }
  return value
}

export function coerceToOptionalNonEmptyString(value: unknown) {
  if (typeof value === 'string' && value.length > 0) return value
  return undefined
}

export function coerceToOptionalTotpSessionData(value: unknown) {
  if (
    typeof value === 'object' &&
    value !== null &&
    'jwe' in value &&
    typeof (value as { jwe: unknown }).jwe === 'string' &&
    'attempts' in value &&
    typeof (value as { attempts: unknown }).attempts === 'number'
  ) {
    return value as TOTPCookieData
  }
  return undefined
}

export function assertTOTPData(obj: unknown): asserts obj is TOTPData {
  if (
    typeof obj !== 'object' ||
    obj === null ||
    !('secret' in obj) ||
    typeof (obj as { secret: unknown }).secret !== 'string' ||
    !('createdAt' in obj) ||
    typeof (obj as { createdAt: unknown }).createdAt !== 'number'
  ) {
    throw new Error('Invalid totp data.')
  }
}