import type { TOTPGenerationOptions } from '../src'

/**
 * Constants.
 */
export const SECRET_ENV =
  'b2FE35059924CDBF5B52A84765B8B010F5291993A9BC39410139D4F511006034'
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
}

export const TOTP_GENERATION_DEFAULTS: Required<
  Pick<TOTPGenerationOptions, 'period' | 'maxAttempts'>
> = {
  period: 60,
  maxAttempts: 3,
}
