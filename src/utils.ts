import type { TOTPGenerationOptions, MagicLinkGenerationOptions } from './index.js'

import { generateTOTP as generateEpicTotp } from '@epic-web/totp'
import { ERRORS } from './constants.js'

import jwt from 'jsonwebtoken'

// @ts-expect-error - `thirty-two` is not typed sadly.
import * as base32 from 'thirty-two'
import * as crypto from 'crypto'

/**
 * TOTP Generation.
 */
export function generateSecret() {
  return base32.encode(crypto.randomBytes(10)).toString() as string
}

export function generateTOTP(options: TOTPGenerationOptions) {
  const code = generateEpicTotp(options)
  return code
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
    options.hostUrl ?? getHostUrl(options.request),
  )
  url.searchParams.set(options.param, options.code)

  return url.toString()
}

/**
 * JWT.
 */
export function signJWT(
  payload: { [key: string]: any },
  expiresIn: string | number,
  secretKey: string,
) {
  try {
    const token = jwt.sign(payload, secretKey, { expiresIn })
    return token
  } catch (err: unknown) {
    throw new Error(ERRORS.INVALID_JWT)
  }
}

export function verifyJWT(token: string, secret: string) {
  try {
    const decoded = jwt.verify(token, secret)
    return decoded
  } catch (err: unknown) {
    throw new Error(ERRORS.INVALID_JWT)
  }
}

/**
 * Miscellaneous.
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
