import type { TOTPData, TOTPSessionData } from './index.js'
import { AuthenticateOptions } from 'remix-auth'
import { generateTOTP as _generateTOTP } from '@epic-web/totp'
import { ERRORS } from './constants.js'

// @ts-expect-error - `thirty-two` is not typed.
import * as base32 from 'thirty-two'
import * as crypto from 'node:crypto'

/**
 * TOTP Generation.
 */
export function generateSecret() {
  return base32.encode(crypto.randomBytes(32)).toString() as string
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

/**
 * Miscellaneous.
 */

export function asJweKey(secret: string) {
  if (!/^[0-9a-fA-F]{64}$/.test(secret)) {
    throw new Error('remix-auth-totp: secret must be a string with 64 hex characters')
  }
  return Buffer.from(secret, 'hex')
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
