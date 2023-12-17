import type { TOTPGenerationOptions, MagicLinkGenerationOptions } from './index.js'

import { SignJWT, jwtVerify } from 'jose'
import { generateTOTP as _generateTOTP } from '@epic-web/totp'

import { ERRORS } from './constants.js'

// @ts-expect-error - `thirty-two` is not typed.
import * as base32 from 'thirty-two'
import * as crypto from 'crypto'

/**
 * TOTP Generation.
 */
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

  const url = new URL(
    options.callbackPath ?? '/',
    options.hostUrl ?? new URL(options.request.url).origin,
  )
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
  try {
    const algorithm = 'HS256'
    const secret = new TextEncoder().encode(secretKey)
    const expires = new Date(Date.now() + expiresIn * 1000)

    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: algorithm })
      .setExpirationTime(expires)
      .setIssuedAt()
      .sign(secret)

    return token
  } catch (err: unknown) {
    throw new Error(ERRORS.INVALID_JWT)
  }
}

type VerifyJWTOptions = {
  jwt: string
  secretKey: string
}

export async function verifyJWT({ jwt, secretKey }: VerifyJWTOptions) {
  try {
    const secret = new TextEncoder().encode(secretKey)
    const { payload } = await jwtVerify(jwt, secret)
    return payload
  } catch (err: unknown) {
    throw new Error(ERRORS.INVALID_JWT)
  }
}

/**
 * Miscellaneous.
 */

/**
 * Returns the host URL.
 * This is no longer called by generateMagicLink() since the host in the request headers
 * may be different from the origin of the request url and the browser would not
 * find the right cookies for the magic link.
 */
export function getHostUrl(request: Request) {
  const host = request.headers.get('X-Forwarded-Host') ?? request.headers.get('host')
  if (!host) throw new Error('Could not determine host.')

  // If the host is localhost or ends with .local, use http.
  const protocol = host.match(/(:?\.local|^localhost|^127\.\d+\.\d+\.\d+)(:?:\d+)?$/)
    ? 'http'
    : 'https'

  return `${protocol}://${host}`
}
