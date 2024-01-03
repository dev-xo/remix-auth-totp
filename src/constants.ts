export const STRATEGY_NAME = 'TOTP'

export const FORM_FIELDS = {
  EMAIL: 'email',
  TOTP: 'code',
} as const

export const SESSION_KEYS = {
  EMAIL: 'auth:email',
  TOTP: 'auth:totp',
  TOTP_EXPIRES_AT: 'auth:totp:expiresAt',
} as const

export const ERRORS = {
  // Customizable errors.
  REQUIRED_EMAIL: 'Email is required.',
  INVALID_EMAIL: 'Email is not valid.',
  INVALID_TOTP: 'Code is not valid.',
  EXPIRED_TOTP: 'Code has expired.',
  INACTIVE_TOTP: 'Code is no longer active.',
  TOTP_NOT_FOUND: 'Database TOTP not found.',

  // Miscellaneous errors.
  REQUIRED_ENV_SECRET: 'Missing required .env secret.',
  USER_NOT_FOUND: 'User not found.',
  INVALID_MAGIC_LINK_PATH: 'Invalid magic-link expected path.',
  REQUIRED_SUCCESS_REDIRECT_URL: 'Missing required successRedirect URL.',
  REQUIRED_FAILURE_REDIRECT_URL: 'Missing required failureRedirect URL.',
  UNKNOWN_ERROR: 'Unknown error.',
} as const
