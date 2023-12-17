import type { AuthenticateOptions } from 'remix-auth'
import type { TOTPGenerationOptions, MagicLinkGenerationOptions } from '../src'

import { createCookieSessionStorage } from '@remix-run/node'

import * as base32 from 'thirty-two'
import * as crypto from 'crypto'

/**
 * Constants.
 */
export const SECRET_ENV = 'SECRET_ENV'
export const HOST_URL = 'http://localhost:3000'
export const DEFAULT_EMAIL = 'localhost@3000.com'

/**
 * Strategy Defaults.
 */
export const AUTH_OPTIONS = {
  name: 'TOTP',
  sessionKey: 'user',
  sessionErrorKey: 'error',
  sessionStrategyKey: 'strategy',
} satisfies AuthenticateOptions

export const TOTP_GENERATION_DEFAULTS = {
  secret: base32.encode(crypto.randomBytes(10)).toString() as string,
  algorithm: 'SHA1',
  charSet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  digits: 6,
  period: 60,
  maxAttempts: 3,
} satisfies TOTPGenerationOptions

export const MAGIC_LINK_GENERATION_DEFAULTS = {
  enabled: true,
  hostUrl: undefined,
  callbackPath: '/magic-link',
} satisfies MagicLinkGenerationOptions

/**
 * Session Storage.
 */
export const sessionStorage = createCookieSessionStorage({
  cookie: { secrets: ['SESSION_SECRET'] },
})
