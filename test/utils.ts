import type { AuthenticateOptions } from 'remix-auth'
import { createCookieSessionStorage } from '@remix-run/node'

import * as base32 from 'thirty-two'
import * as crypto from 'crypto'

/**
 * Constants.
 */
export const SECRET_ENV = 'STRONG_SECRET_KEY'
export const HOST_URL = 'localhost:3000'

/**
 * Strategy Defaults.
 */
export const AUTH_OPTIONS: AuthenticateOptions = {
  name: 'TOTP',
  sessionKey: 'user',
  sessionErrorKey: 'error',
  sessionStrategyKey: 'strategy',
}

export const TOTP_DEFAULTS = {
  secret: base32.encode(crypto.randomBytes(10)).toString() as string,
  algorithm: 'SHA1',
  charSet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  digits: 6,
  period: 60,
  maxAttempts: 3,
}

export const MAGIC_LINK_DEFAULTS = {
  enabled: true,
  originUrl: undefined,
  callbackPath: '/magic-link',
}

/**
 * Session Storage.
 */
export const sessionStorage = createCookieSessionStorage({
  cookie: { secrets: ['SESSION_SECRET_KEY'] },
})
