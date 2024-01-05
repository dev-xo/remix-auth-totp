import type { AuthenticateOptions } from 'remix-auth'
import type { TOTPGenerationOptions } from '../src'

import { createCookieSessionStorage } from '@remix-run/node'

import * as base32 from 'thirty-two'
import * as crypto from 'crypto'

/**
 * Constants.
 */
export const SECRET_ENV = 'SECRET_ENV'
export const HOST_URL = 'https://prodserver.com'
export const DEFAULT_EMAIL = 'user@gmail.com'
export const MAGIC_LINK_PATH = '/magic-link'

/**
 * Strategy Defaults.
 */
export const AUTH_OPTIONS = {
  name: 'TOTP',
  sessionKey: 'user',
  sessionErrorKey: 'error',
  sessionStrategyKey: 'strategy',
} satisfies AuthenticateOptions

export const TOTP_GENERATION_DEFAULTS: Required<TOTPGenerationOptions> = {
  secret: base32.encode(crypto.randomBytes(10)).toString() as string,
  algorithm: 'SHA1',
  charSet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  digits: 6,
  period: 60,
  maxAttempts: 3,
}

/**
 * Session Storage.
 */
export const sessionStorage = createCookieSessionStorage({
  cookie: { secrets: ['SESSION_SECRET'] },
})
