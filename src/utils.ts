import type {
  TOTPGenerationOptions,
  MagicLinkGenerationOptions,
  TOTPData,
} from './index.js'
import { SignJWT, jwtVerify } from 'jose'
import { generateTOTP as _generateTOTP } from '@epic-web/totp'
import { ERRORS } from './constants.js'

// @ts-expect-error - `thirty-two` is not typed.
import * as base32 from 'thirty-two'
import * as crypto from 'crypto'
import { AuthenticateOptions } from 'remix-auth'

/**
 * TOTP Generation.
 */

type TOTPPayload = Omit<ReturnType<typeof _generateTOTP>, "otp">

export function generateSecret() {
  return base32.encode(crypto.randomBytes(10)).toString() as string
}

export function generateTOTP(options: TOTPGenerationOptions) {
  return _generateTOTP(options)
}

export function generateMagicLink(
  options: MagicLinkGenerationOptions & {
    code: string
    param: string
    request: Request
  },
) {
  if (!options.enabled) {
    return undefined
  }

  const url = new URL(options.callbackPath ?? '/', new URL(options.request.url).origin)
  url.searchParams.set(options.param, options.code)

  return url.toString()
}

/**
 * JSON Web Token (JWT).
 */
type SignJWTOptions = {
  payload: { [key: string]: any }
  expiresIn: number
  secretKey: string
}

export async function signJWT({ payload, expiresIn, secretKey }: SignJWTOptions) {
  const algorithm = 'HS256'
  const secret = new TextEncoder().encode(secretKey)
  const expires = new Date(Date.now() + expiresIn * 1000)

  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: algorithm })
    .setExpirationTime(expires)
    .setIssuedAt()
    .sign(secret)

  return token
}

type VerifyJWTOptions = {
  jwt: string
  secretKey: string
}

export async function verifyJWT({ jwt, secretKey }: VerifyJWTOptions) {
  const secret = new TextEncoder().encode(secretKey)
  const { payload } = await jwtVerify(jwt, secret)
  return payload
}

/**
 * Miscellaneous.
 */

export function coerceToOptionalNonEmptyString(value: unknown) {
  if (typeof value === 'string' && value.length > 0) return value
  return undefined
}

export function coerceToOptionalString(value: unknown) {
  if (typeof value !== 'string' && value !== undefined) {
    throw new Error('Value must be a string or undefined.')
  }
  return value
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
