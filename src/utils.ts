import type { TOTPGenerationOptions, TOTPData } from './index.js'
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
  return base32.encode(crypto.randomBytes(10)).toString() as string
}

export function generateTOTP(options: TOTPGenerationOptions) {
  return _generateTOTP(options)
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

export function coerceToOptionalTotpData(value: unknown) {
  if (
    typeof value === 'object' &&
    value !== null &&
    'hash' in value &&
    typeof (value as { hash: unknown }).hash === 'string' &&
    'attempts' in value &&
    typeof (value as { attempts: unknown }).attempts === 'number'
  ) {
    return value as TOTPData
  }
  return undefined
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
