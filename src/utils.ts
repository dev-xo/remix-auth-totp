import type { TOTPData, TOTPSessionData } from './index.js'
import type { AuthenticateOptions } from 'remix-auth'
import { ERRORS } from './constants.js'

import base32Encode from 'base32-encode'
import * as crypto from 'node:crypto'

/**
 * TOTP Generation.
 */
export function generateSecret() {
  return base32Encode(crypto.randomBytes(32), 'RFC4648').toString() as string
}

export function generateMagicLink(options: {
  code: string
  magicLinkPath: string
  param: string
  request: Request
}) {
  const url = new URL(options.magicLinkPath ?? '/', new URL(options.request.url).origin)
  url.searchParams.set(options.param, options.code)

  return url.toString()
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
};
function hexToUint8Array(hexString: string) {
	if (hexString.length % 2 !== 0) {
		throw new Error('Invalid Hex string length.');
	}

	const resultLength = hexString.length / 2;
	const bytes = new Uint8Array(resultLength);

	for (let index = 0; index < resultLength; index++) {
		const highNibble = hexToDecimalLookupTable[hexString[index * 2]];
		const lowNibble = hexToDecimalLookupTable[hexString[(index * 2) + 1]];

		if (highNibble === undefined || lowNibble === undefined) {
			throw new Error(`Invalid Hex character encountered at position ${index * 2}`);
		}

		bytes[index] = (highNibble << 4) | lowNibble;
	}

	return bytes;
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
    return value as TOTPSessionData
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

export type RequiredAuthenticateOptions = Required<
  Pick<AuthenticateOptions, 'failureRedirect' | 'successRedirect'>
> &
  Omit<AuthenticateOptions, 'failureRedirect' | 'successRedirect'>

export function assertIsRequiredAuthenticateOptions(
  options: AuthenticateOptions,
): asserts options is RequiredAuthenticateOptions {
  if (options.successRedirect === undefined) {
    throw new Error(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)
  }
  if (options.failureRedirect === undefined) {
    throw new Error(ERRORS.REQUIRED_FAILURE_REDIRECT_URL)
  }
}
