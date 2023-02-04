import type { AuthenticateOptions } from 'remix-auth'
import { createCookieSessionStorage } from '@remix-run/node'
import { vi } from 'vitest'

/**
 * Constants.
 */
export const HOST_URL = 'localhost:3000'
export const SECRET_ENV = 'SECRET'

/**
 * Strategy Instance Defaults.
 */
export const BASE_OPTIONS: AuthenticateOptions = {
  name: 'OTP',
  sessionKey: 'user',
  sessionErrorKey: 'error',
  sessionStrategyKey: 'strategy',
}

export const OTP_DEFAULTS = {
  expiresAt: 1000 * 60 * 15,
  length: 6,
  digits: false,
  lowerCaseAlphabets: false,
  upperCaseAlphabets: true,
  specialChars: false,
}

export const MAGIC_LINK_DEFAULTS = {
  enabled: true,
  baseUrl: undefined,
  callbackPath: '/magic-link',
}

/**
 * Session Storage.
 */
export const sessionStorage = createCookieSessionStorage({
  cookie: { secrets: ['SESSION_SECRET_KEY'] },
})

/**
 * Mocks.
 */
export const verify = vi.fn()
export const storeCode = vi.fn()
export const sendCode = vi.fn()
export const validateCode = vi.fn()
export const invalidateCode = vi.fn()
