export const STRATEGY_NAME = 'TOTP'

export const FORM_FIELDS = {
  EMAIL: 'email',
  CODE: 'code',
} as const

export const SESSION_KEYS = {
  EMAIL: 'auth:email',
  TOTP: 'auth:totp',
} as const

export const ERRORS = {
  // Customizable errors.
  REQUIRED_EMAIL: 'Please enter your email address to continue.',
  INVALID_EMAIL:
    "That doesn't look like a valid email address. Please check and try again.",
  INVALID_TOTP:
    "That code didn't work. Please check and try again, or request a new code.",
  EXPIRED_TOTP: 'That code has expired. Please request a new one.',
  MISSING_SESSION_EMAIL:
    "We couldn't find an email to verify. Please use the same browser you started with or restart from this browser.",
  MISSING_SESSION_TOTP:
    "We couldn't find an active verification session. Please request a new code.",
  RATE_LIMIT_EXCEEDED: "Too many incorrect attempts. Please request a new code.",

  // Miscellaneous errors.
  REQUIRED_ENV_SECRET: 'Missing required .env secret.',
  USER_NOT_FOUND: 'User not found.',
  INVALID_MAGIC_LINK_PATH: 'Invalid magic-link expected path.',
  REQUIRED_EMAIL_SENT_REDIRECT_URL: 'Missing required emailSentRedirect URL.',
  REQUIRED_SUCCESS_REDIRECT_URL: 'Missing required successRedirect URL.',
  REQUIRED_FAILURE_REDIRECT_URL: 'Missing required failureRedirect URL.',
} as const
