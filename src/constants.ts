export const STRATEGY_NAME = 'TOTP'

export const FORM_FIELDS = {
  EMAIL: 'email',
  TOTP: 'code',
} as const

export const SESSION_KEYS = {
  EMAIL: 'auth:email',
  TOTP: 'auth:totp',
} as const

export const ERRORS = {
  // Customizable errors.
  INVALID_EMAIL: 'Email is not valid.',
  INVALID_TOTP: 'Code is not valid.',
  EXPIRED_TOTP: 'Code has expired.',

  // Miscellaneous errors.
  REQUIRED_ENV_SECRET: 'Missing required .env secret.',
  USER_NOT_FOUND: 'User not found.',
  INVALID_MAGIC_LINK_PATH: 'Invalid magic-link expected path.',
  REQUIRED_SUCCESS_REDIRECT_URL: 'Missing required successRedirect URL.',
  REQUIRED_FAILURE_REDIRECT_URL: 'Missing required failureRedirect URL.',
} as const
