import type { Session, SessionStorage } from '@remix-run/server-runtime'
import type { AuthenticateOptions, StrategyVerifyCallback } from 'remix-auth'
import { errors } from 'jose'

import { redirect } from '@remix-run/server-runtime'
import { Strategy } from 'remix-auth'
import { verifyTOTP } from '@epic-web/totp'
import {
  generateSecret,
  generateTOTP,
  generateMagicLink,
  signJWT,
  verifyJWT,
  ensureStringOrUndefined,
  ensureObjectOrUndefined,
  ensureNonEmptyStringOrNull,
  assertIsRequiredAuthenticateOptions,
  RequiredAuthenticateOptions,
} from './utils.js'
import { STRATEGY_NAME, FORM_FIELDS, SESSION_KEYS, ERRORS } from './constants.js'

/**
 * The TOTP data stored in the session.
 */
export interface TOTPData {
  /**
   * The encrypted TOTP.
   */
  hash: string

  /**
   * The expiration date for the TOTP secret.
   * After this date, the TOTP will no longer be valid.
   */
  expiresAt: Date

  /**
   * The number of attempts the user tried to verify the TOTP.
   * @default 0
   */
  attempts: number
}

/**
 * The TOTP data the application stores.
 * Used in CRUD functions provided by the application.
 */
export interface TOTPDataDeprecated {
  /**
   * The encrypted TOTP.
   */
  hash: string

  /**
   * The status of the TOTP.
   * @default true
   */
  active: boolean

  /**
   * The number of attempts the user tried to verify the TOTP.
   * @default 0
   */
  attempts: number
}

/**
 * The TOTP generation configuration.
 */
export interface TOTPGenerationOptions {
  /**
   * The secret used to generate the TOTP.
   * It should be Base32 encoded (Feel free to use: https://npm.im/thirty-two).
   *
   * @default random Base32 secret.
   */
  secret?: string

  /**
   * The algorithm used to generate the TOTP.
   * @default 'SHA1'
   */
  algorithm?: string

  /**
   * The character set used to generate the TOTP.
   * @default 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
   */
  charSet?: string

  /**
   * The number of digits used to generate the TOTP.
   * @default 6
   */
  digits?: number

  /**
   * The number of seconds the TOTP will be valid.
   * @default 60
   */
  period?: number

  /**
   * The max number of attempts the user can try to verify the TOTP.
   * @default 3
   */
  maxAttempts?: number
}

/**
 * The magic-link configuration.
 */
export interface MagicLinkGenerationOptions {
  /**
   * Whether to enable the Magic Link generation.
   * @default true
   */
  enabled?: boolean

  /**
   * The callback URL path for the Magic Link.
   * @default '/magic-link'
   */
  callbackPath?: string
}

/**
 * The send TOTP configuration.
 */
export interface SendTOTPOptions {
  /**
   * The email address provided by the user.
   */
  email: string

  /**
   * The decrypted TOTP code.
   */
  code: string

  /**
   * The Magic Link URL.
   */
  magicLink?: string

  /**
   * The formData object.
   */
  form?: FormData

  /**
   * The Request object.
   */
  request: Request
}

/**
 * The sender email method.
 * @param options The send TOTP options.
 */
export interface SendTOTP {
  (options: SendTOTPOptions): Promise<void>
}

/**
 * The validate email method.
 * This can be useful to ensure it's not a disposable email address.
 *
 * @param email The email address to validate.
 */
export interface ValidateEmail {
  (email: string): Promise<void>
}

/**
 * The custom errors configuration.
 */
export interface CustomErrorsOptions {
  /**
   * The required email error message.
   */
  requiredEmail?: string

  /**
   * The invalid email error message.
   */
  invalidEmail?: string

  /**
   * The invalid TOTP error message.
   */
  invalidTotp?: string

  /**
   * The expired TOTP error message.
   */
  expiredTotp?: string

  /**
   * The inactive TOTP error message.
   */
  inactiveTotp?: string

  /**
   * The TOTP not found error message.
   */
  totpNotFound?: string
}

/**
 * The TOTP Strategy options.
 */
export interface TOTPStrategyOptions {
  /**
   * The secret used to sign the JWT.
   */
  secret: string

  /**
   * The maximum age the session can live.
   * @default undefined
   */
  maxAge?: number

  /**
   * The TOTP generation configuration.
   */
  totpGeneration?: TOTPGenerationOptions

  /**
   * The Magic Link configuration.
   */
  magicLinkGeneration?: MagicLinkGenerationOptions

  /**
   * The send TOTP method.
   */
  sendTOTP: SendTOTP

  /**
   * The validate email method.
   */
  validateEmail?: ValidateEmail

  /**
   * The custom errors configuration.
   */
  customErrors?: CustomErrorsOptions

  /**
   * The form input name used to get the email address.
   * @default "email"
   */
  emailFieldKey?: string

  /**
   * The form input name used to get the TOTP.
   * @default "totp"
   */
  totpFieldKey?: string

  /**
   * The session key that stores the email address.
   * @default "auth:email"
   */
  sessionEmailKey?: string

  /**
   * The session key that stores the signed TOTP.
   * @default "auth:totp"
   */
  sessionTotpKey?: string

  /**
   * The session key that stores the expiration of the TOTP.
   * @default "auth:totpExpiresAt"
   */
  sessionTotpExpiresAtKey?: string
}

/**
 * The verify method callback.
 * Returns required data to verify the user and handle additional logic.
 */
export interface TOTPVerifyParams {
  /**
   * The email address provided by the user.
   */
  email: string

  /**
   * The TOTP code.
   */
  code?: string

  /**
   * The Magic Link URL.
   */
  magicLink?: string

  /**
   * The formData object from the Request.
   */
  form?: FormData

  /**
   * The Request object.
   */
  request: Request
}

export class TOTPStrategy<User> extends Strategy<User, TOTPVerifyParams> {
  public name = STRATEGY_NAME

  private readonly secret: string
  private readonly maxAge: number | undefined
  private readonly totpGeneration: TOTPGenerationOptions
  private readonly magicLinkGeneration: MagicLinkGenerationOptions
  private readonly sendTOTP: SendTOTP
  private readonly validateEmail: ValidateEmail
  private readonly customErrors: Required<CustomErrorsOptions>
  private readonly emailFieldKey: string
  private readonly totpFieldKey: string
  private readonly sessionEmailKey: string
  private readonly sessionTotpKey: string
  private readonly sessionTotpExpiresAtKey: string

  private readonly _totpGenerationDefaults = {
    secret: generateSecret(),
    algorithm: 'SHA1',
    charSet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    digits: 6,
    period: 60,
    maxAttempts: 3,
  } satisfies TOTPGenerationOptions
  private readonly _magicLinkGenerationDefaults = {
    enabled: true,
    callbackPath: '/magic-link',
  } satisfies MagicLinkGenerationOptions
  private readonly _customErrorsDefaults = {
    requiredEmail: ERRORS.REQUIRED_EMAIL,
    invalidEmail: ERRORS.INVALID_EMAIL,
    invalidTotp: ERRORS.INVALID_TOTP,
    expiredTotp: ERRORS.EXPIRED_TOTP,
    inactiveTotp: ERRORS.INACTIVE_TOTP,
    totpNotFound: ERRORS.TOTP_NOT_FOUND,
  } satisfies CustomErrorsOptions

  constructor(
    options: TOTPStrategyOptions,
    verify: StrategyVerifyCallback<User, TOTPVerifyParams>,
  ) {
    super(verify)
    this.secret = options.secret
    this.maxAge = options.maxAge ?? undefined
    this.sendTOTP = options.sendTOTP
    this.validateEmail = options.validateEmail ?? this._validateEmailDefaults
    this.emailFieldKey = options.emailFieldKey ?? FORM_FIELDS.EMAIL
    this.totpFieldKey = options.totpFieldKey ?? FORM_FIELDS.TOTP
    this.sessionEmailKey = options.sessionEmailKey ?? SESSION_KEYS.EMAIL
    this.sessionTotpKey = options.sessionTotpKey ?? SESSION_KEYS.TOTP
    this.sessionTotpExpiresAtKey =
      options.sessionTotpExpiresAtKey ?? SESSION_KEYS.TOTP_EXPIRES_AT

    this.totpGeneration = {
      ...this._totpGenerationDefaults,
      ...options.totpGeneration,
    }
    this.magicLinkGeneration = {
      ...this._magicLinkGenerationDefaults,
      ...options.magicLinkGeneration,
    }
    this.customErrors = {
      ...this._customErrorsDefaults,
      ...options.customErrors,
    }
  }

  /**
   * Authenticates a user using TOTP.
   *
   * If the user is already authenticated, simply returns the user.
   *
   * | Method | Email | TOTP | Sess. Email | Sess. TOTP | Action/Logic                                                                                                   |
   * |--------|-------|------|-------------|------------|----------------------------------------------------------------------------------------------------------------|
   * | POST   | ✓     | ✗    | -           | -          | Generate new TOTP, send to user, store email and TOTP in session.                                              |
   * | POST   | ✗     | ✓    | ✓           | ✓          | Validate TOTP against session. If valid, authenticate user.                                                    |
   * | POST   | ✗     | ✗    | ✓           | ✓          | Invalidate previous TOTP, generate new one if session has email and TOTP.                                      |
   * | POST   | ≠     | -    | ✓           | ✓          | Invalidate previous TOTP, generate new TOTP for new email.                                                     |
   * | GET    | -     | -    | -           | -          | If magic-link enabled and URL has TOTP, validate it. If valid, authenticate user.                              |
   *
   * | Method | Email | TOTP | Sess. Email | Sess. TOTP | Action/Logic                             |
   * |--------|-------|------|-------------|------------|------------------------------------------|
   * | POST   | ✓     | -    | -           | -          | Generate/send TOTP using form email.     |
   * | POST   | ✗     | ✗    | ✓           | -          | Generate/send TOTP for session email.    |
   * | POST   | ✗     | ✓    | ✓           | ✓          | Validate form TOTP.                      |
   * | GET    | -     | -    | ✓           | ✓          | Validate magic link TOTP.                |
   *
   * @param {Request} request - The request object.
   * @param {SessionStorage} sessionStorage - The session storage instance.
   * @param {AuthenticateOptions} options - The authentication options. successRedirect is required.
   * @returns {Promise<User>} The authenticated user.
   */
  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions,
  ): Promise<User> {
    if (!this.secret) throw new Error(ERRORS.REQUIRED_ENV_SECRET)
    assertIsRequiredAuthenticateOptions(options)

    const session = await sessionStorage.getSession(request.headers.get('cookie'))
    const user: User | null = session.get(options.sessionKey) ?? null
    if (user) return this.success(user, request, sessionStorage, options)

    const formData = request.method === 'POST' ? await request.formData() : new FormData()
    const formDataEmail = ensureNonEmptyStringOrNull(formData.get(this.emailFieldKey))
    const formDataTotp = ensureNonEmptyStringOrNull(formData.get(this.totpFieldKey))
    const sessionEmail = ensureStringOrUndefined(session.get(this.sessionEmailKey))
    const sessionTotp = ensureObjectOrUndefined(session.get(this.sessionTotpKey))
    const email =
      request.method === 'POST'
        ? formDataEmail ?? (!formDataTotp ? sessionEmail : null)
        : null
    console.log('authenticate:', {
      formDataEmail,
      formDataTotp,
      sessionEmail,
      sessionTotp,
      email,
    })
    try {
      if (email) {
        await this._generateAndSendTOTP({
          email,
          session,
          sessionStorage,
          request,
          formData,
          options,
        })
      }
      const code = formDataTotp ?? this._getMagicLinkCode(request)
      if (code) {
        if (!sessionEmail || !sessionTotp) throw new Error(ERRORS.EXPIRED_TOTP)
        await this._validateTOTP({
          code,
          sessionTotp: sessionTotp as TOTPData,
          session,
          sessionStorage,
          options,
        })

        // Allow developer to handle user validation.
        const user = await this.verify({
          email: sessionEmail,
          form: formData,
          request,
        })
        console.log('authenticate: user', user)

        session.set(options.sessionKey, user)
        session.unset(this.sessionEmailKey)
        session.unset(this.sessionTotpKey)
        session.unset(options.sessionErrorKey)

        throw redirect(options.successRedirect, {
          headers: {
            'set-cookie': await sessionStorage.commitSession(session, {
              maxAge: this.maxAge,
            }),
          },
        })
      }
    } catch (throwable) {
      if (throwable instanceof Response) throw throwable
      if (throwable instanceof Error) {
        console.log('authenticate: error:', throwable.message)
        return await this.failure(
          throwable.message,
          request,
          sessionStorage,
          options,
          throwable,
        )
      }
      throw throwable
    }
    throw new Error('Not implemented.')
  }

  private async _generateAndSendTOTP({
    email,
    session,
    sessionStorage,
    request,
    formData,
    options,
  }: {
    email: string
    session: Session
    sessionStorage: SessionStorage
    request: Request
    formData: FormData
    options: AuthenticateOptions
  }) {
    console.log('_generateAndSendTOTP:', { email })
    if (!options.successRedirect) throw new Error(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)

    await this.validateEmail(email)
    const { otp: code, ...totp } = generateTOTP({
      ...this.totpGeneration,
      secret: generateSecret(),
    })
    const hash = await signJWT({
      payload: totp,
      expiresIn: this.totpGeneration.period ?? this._totpGenerationDefaults.period,
      secretKey: this.secret,
    })
    const magicLink = generateMagicLink({
      ...this.magicLinkGeneration,
      code,
      param: this.totpFieldKey,
      request,
    })
    await this.sendTOTP({
      email,
      code,
      magicLink,
      form: formData,
      request,
    })

    const expiresAtEpochMs = // (Milliseconds since Unix epoch).
      Date.now() + (totp.period ?? this._totpGenerationDefaults.period) * 1000
    const totpData: TOTPData = {
      hash,
      expiresAt: new Date(expiresAtEpochMs),
      attempts: 0,
    }
    session.set(this.sessionEmailKey, email)
    session.set(this.sessionTotpKey, totpData)
    session.unset(options.sessionErrorKey)
    throw redirect(options.successRedirect, {
      headers: {
        'set-cookie': await sessionStorage.commitSession(session, {
          maxAge: this.maxAge,
        }),
      },
    })
  }

  private _getMagicLinkCode(request: Request) {
    if (request.method === 'GET') {
      if (this.magicLinkGeneration.enabled) {
        const url = new URL(request.url)
        if (url.pathname !== this.magicLinkGeneration.callbackPath) {
          throw new Error(ERRORS.INVALID_MAGIC_LINK_PATH)
        }
        if (url.searchParams.has(this.totpFieldKey)) {
          return decodeURIComponent(url.searchParams.get(this.totpFieldKey) ?? '')
        }
      }
    }
    return null
  }

  private async _validateEmailDefaults(email: string) {
    const regexEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/gm
    if (!regexEmail.test(email)) throw new Error(this.customErrors.invalidEmail)
  }

  private async _validateTOTP({
    code,
    sessionTotp,
    session,
    sessionStorage,
    options,
  }: {
    code: string
    sessionTotp: TOTPData
    session: Session
    sessionStorage: SessionStorage
    options: RequiredAuthenticateOptions
  }) {
    try {
      console.log('_validateTOTP:', { code, sessionTotp })
      // Decryption and Verification.
      const { ...totp } = (await verifyJWT({
        jwt: sessionTotp.hash,
        secretKey: this.secret,
      })) as Required<TOTPGenerationOptions>
      console.log('_validateTOTP: totp:', totp)

      // Verify TOTP (@epic-web/totp).
      if (!verifyTOTP({ ...totp, otp: code }))
        throw new Error(this.customErrors.invalidTotp)
    } catch (error) {
      console.error('_validateTOTP: error:', error)
      if (error instanceof errors.JWTExpired) {
        session.unset(this.sessionTotpKey)
        session.flash(options.sessionErrorKey, { message: this.customErrors.expiredTotp })
      } else {
        sessionTotp.attempts += 1
        const maxAttempts =
          this.totpGeneration.maxAttempts ?? this._totpGenerationDefaults.maxAttempts
        if (sessionTotp.attempts >= maxAttempts) {
          session.unset(this.sessionTotpKey)
        } else {
          session.set(this.sessionTotpKey, sessionTotp)
        }
        session.flash(options.sessionErrorKey, { message: this.customErrors.invalidTotp })
      }
      throw redirect(options.failureRedirect, {
        headers: {
          'set-cookie': await sessionStorage.commitSession(session, {
            maxAge: this.maxAge,
          }),
        },
      })
    }
  }
}
