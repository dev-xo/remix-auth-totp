import type { Session, SessionStorage } from '@remix-run/server-runtime'
import type { AuthenticateOptions, StrategyVerifyCallback } from 'remix-auth'

import { redirect } from '@remix-run/server-runtime'
import { Strategy } from 'remix-auth'
import { verifyTOTP } from '@epic-web/totp'
import { errors } from 'jose'
import {
  generateSecret,
  generateTOTP,
  generateMagicLink,
  signJWT,
  verifyJWT,
  coerceToOptionalString,
  coerceToOptionalTotpData,
  coerceToOptionalNonEmptyString,
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
  magicLink: string

  /**
   * The request to generate the TOTP.
   */
  request: Request

  /**
   * The form data of the request.
   */
  formData: FormData
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
  (email: string): Promise<boolean>
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
   * The URL path for the Magic Link.
   * @default '/magic-link'
   */
  magicLinkPath?: string

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
   * @default "code"
   */
  codeFieldKey?: string

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
   * The send TOTP method.
   */
  sendTOTP: SendTOTP

  /**
   * The validate email method.
   */
  validateEmail?: ValidateEmail
}

/**
 * The verify method callback.
 * Returns the user for the email to be stored in the session.
 */
export interface TOTPVerifyParams {
  /**
   * The email address provided by the user.
   */
  email: string

  /**
   * The formData object from the Request.
   */
  formData?: FormData

  /**
   * The Request object.
   */
  request: Request
}

export class TOTPStrategy<User> extends Strategy<User, TOTPVerifyParams> {
  public name = STRATEGY_NAME

  private readonly secret: string
  private readonly maxAge: number | undefined
  private readonly totpGeneration: Required<TOTPGenerationOptions>
  private readonly magicLinkPath: string
  private readonly customErrors: Required<CustomErrorsOptions>
  private readonly emailFieldKey: string
  private readonly codeFieldKey: string
  private readonly sessionEmailKey: string
  private readonly sessionTotpKey: string
  private readonly sendTOTP: SendTOTP
  private readonly validateEmail: ValidateEmail

  private readonly _totpGenerationDefaults: Required<TOTPGenerationOptions> = {
    secret: generateSecret(),
    algorithm: 'SHA1',
    charSet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    digits: 6,
    period: 60,
    maxAttempts: 3,
  }
  private readonly _customErrorsDefaults: Required<CustomErrorsOptions> = {
    requiredEmail: ERRORS.REQUIRED_EMAIL,
    invalidEmail: ERRORS.INVALID_EMAIL,
    invalidTotp: ERRORS.INVALID_TOTP,
    expiredTotp: ERRORS.EXPIRED_TOTP,
  }

  constructor(
    options: TOTPStrategyOptions,
    verify: StrategyVerifyCallback<User, TOTPVerifyParams>,
  ) {
    super(verify)
    this.secret = options.secret
    this.maxAge = options.maxAge
    this.magicLinkPath = options.magicLinkPath ?? '/magic-link'
    this.emailFieldKey = options.emailFieldKey ?? FORM_FIELDS.EMAIL
    this.codeFieldKey = options.codeFieldKey ?? FORM_FIELDS.CODE
    this.sessionEmailKey = options.sessionEmailKey ?? SESSION_KEYS.EMAIL
    this.sessionTotpKey = options.sessionTotpKey ?? SESSION_KEYS.TOTP
    this.sendTOTP = options.sendTOTP
    this.validateEmail = options.validateEmail ?? this._validateEmailDefault

    this.totpGeneration = {
      ...this._totpGenerationDefaults,
      ...options.totpGeneration,
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
   * | Method | Email | Code | Sess. Email | Sess. TOTP | Action/Logic                             |
   * |--------|-------|------|-------------|------------|------------------------------------------|
   * | POST   | ✓     | -    | -           | -          | Generate/send TOTP using form email.     |
   * | POST   | ✗     | ✗    | ✓           | -          | Generate/send TOTP using session email.  |
   * | POST   | ✗     | ✓    | ✓           | ✓          | Validate form TOTP code.                 |
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
    const formDataEmail = coerceToOptionalNonEmptyString(formData.get(this.emailFieldKey))
    const formDataCode = coerceToOptionalNonEmptyString(formData.get(this.codeFieldKey))
    const sessionEmail = coerceToOptionalString(session.get(this.sessionEmailKey))
    const sessionTotp = coerceToOptionalTotpData(session.get(this.sessionTotpKey))
    const email =
      request.method === 'POST'
        ? formDataEmail ?? (!formDataCode ? sessionEmail : null)
        : null

    try {
      if (email) {
        // Generate and Send TOTP.
        const { code, hash, magicLink } = await this._generateTOTP({ email, request })
        await this.sendTOTP({
          email,
          code,
          magicLink,
          formData,
          request,
        })

        const totpData: TOTPData = { hash, attempts: 0 }
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

      const code = formDataCode ?? this._getMagicLinkCode(request)
      if (code) {
        // Validate TOTP.
        if (!sessionEmail || !sessionTotp) throw new Error(this.customErrors.expiredTotp)
        await this._validateTOTP({ code, sessionTotp, session, sessionStorage, options })

        const user = await this.verify({
          email: sessionEmail,
          formData: request.method === 'POST' ? formData : undefined,
          request,
        })

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
      throw new Error(this.customErrors.requiredEmail)
    } catch (throwable) {
      if (throwable instanceof Response) throw throwable
      if (throwable instanceof Error) {
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
  }

  private async _generateTOTP({ email, request }: { email: string; request: Request }) {
    const isValidEmail = await this.validateEmail(email)
    if (!isValidEmail) throw new Error(this.customErrors.invalidEmail)

    const { otp: code, ...totpPayload } = generateTOTP({
      ...this.totpGeneration,
      secret: generateSecret(),
    })
    const hash = await signJWT({
      payload: totpPayload,
      expiresIn: this.totpGeneration.period,
      secretKey: this.secret,
    })
    const magicLink = generateMagicLink({
      code,
      magicLinkPath: this.magicLinkPath,
      param: this.codeFieldKey,
      request,
    })

    return { code, hash, magicLink }
  }

  private _getMagicLinkCode(request: Request) {
    if (request.method === 'GET') {
      const url = new URL(request.url)
      if (url.pathname !== this.magicLinkPath) {
        throw new Error(ERRORS.INVALID_MAGIC_LINK_PATH)
      }
      if (url.searchParams.has(this.codeFieldKey)) {
        return decodeURIComponent(url.searchParams.get(this.codeFieldKey) ?? '')
      }
    }
    return undefined
  }

  private async _validateEmailDefault(email: string) {
    const regexEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/gm
    return regexEmail.test(email)
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
      // Decryption and Verification.
      const totpPayload = await verifyJWT({
        jwt: sessionTotp.hash,
        secretKey: this.secret,
      })

      // Verify TOTP (@epic-web/totp).
      if (!verifyTOTP({ ...totpPayload, otp: code })) {
        throw new Error(this.customErrors.invalidTotp)
      }
    } catch (error) {
      if (error instanceof errors.JWTExpired) {
        session.unset(this.sessionTotpKey)
        session.flash(options.sessionErrorKey, { message: this.customErrors.expiredTotp })
      } else {
        sessionTotp.attempts += 1
        if (sessionTotp.attempts >= this.totpGeneration.maxAttempts) {
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
