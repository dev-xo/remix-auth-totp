import type { Session, SessionStorage, AppLoadContext } from '@remix-run/server-runtime'
import type { AuthenticateOptions, StrategyVerifyCallback } from 'remix-auth'

import { redirect } from '@remix-run/server-runtime'
import { Strategy } from 'remix-auth'
import { generateTOTP, verifyTOTP } from '@epic-web/totp'
import * as jose from 'jose'
import {
  generateSecret,
  generateMagicLink,
  coerceToOptionalString,
  coerceToOptionalTotpSessionData,
  coerceToOptionalNonEmptyString,
  assertIsRequiredAuthenticateOptions,
  RequiredAuthenticateOptions,
  assertTOTPData,
  asJweKey,
} from './utils.js'
import { STRATEGY_NAME, FORM_FIELDS, SESSION_KEYS, ERRORS } from './constants.js'

/**
 * The TOTP data stored in the session.
 */
export interface TOTPSessionData {
  /**
   * The TOTP JWE of TOTPData.
   */
  jwe: string

  /**
   * The number of attempts the user tried to verify the TOTP.
   * @default 0
   */
  attempts: number
}

/**
 * The TOTP JWE data containing the secret.
 */
export interface TOTPData {
  /**
   * The TOTP secret.
   */
  secret: string

  /**
   * The time the TOTP was generated.
   */
  createdAt: number
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

  /**
   * The context object received by the loader or action.
   * Defaults to undefined.
   * Explicitly include it in the options to authenticate if you need it.
   */
  context?: AppLoadContext
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
   * The secret used to encrypt the TOTP data.
   * Must be string of 64 hexadecimal characters.
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

  /**
   * The context object received by the loader or action.
   * Defaults to undefined.
   * Explicitly include it in the options to authenticate if you need it.
   */
  context?: AppLoadContext
}

export class TOTPStrategy<User> extends Strategy<User, TOTPVerifyParams> {
  public name = STRATEGY_NAME

  private readonly secret: string
  private readonly maxAge: number | undefined
  private readonly totpGeneration: Pick<TOTPGenerationOptions, 'secret'> &
    Required<Omit<TOTPGenerationOptions, 'secret'>>
  private readonly magicLinkPath: string
  private readonly customErrors: Required<CustomErrorsOptions>
  private readonly emailFieldKey: string
  private readonly codeFieldKey: string
  private readonly sessionEmailKey: string
  private readonly sessionTotpKey: string
  private readonly sendTOTP: SendTOTP
  private readonly validateEmail: ValidateEmail
  private readonly _totpGenerationDefaults = {
    algorithm: 'SHA256', // More secure than SHA1
    charSet: 'abcdefghijklmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ123456789', // No O or 0
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

    const formData = await this._readFormData(request, options)
    const formDataEmail = coerceToOptionalNonEmptyString(formData.get(this.emailFieldKey))
    const formDataCode = coerceToOptionalNonEmptyString(formData.get(this.codeFieldKey))
    const sessionEmail = coerceToOptionalString(session.get(this.sessionEmailKey))
    const sessionTotp = coerceToOptionalTotpSessionData(session.get(this.sessionTotpKey))
    const email =
      request.method === 'POST'
        ? formDataEmail ?? (!formDataCode ? sessionEmail : null)
        : null

    try {
      if (email) {
        const { code, jwe, magicLink } = await this._generateTOTP({ email, request })
        await this.sendTOTP({
          email,
          code,
          magicLink,
          formData,
          request,
          context: options.context,
        })

        const totpData: TOTPSessionData = { jwe, attempts: 0 }
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
        if (!sessionEmail || !sessionTotp) throw new Error(this.customErrors.expiredTotp)
        await this._validateTOTP({ code, sessionTotp, session, sessionStorage, options })

        const user = await this.verify({
          email: sessionEmail,
          formData: request.method === 'POST' ? formData : undefined,
          request,
          context: options.context,
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

    const { otp: code, secret } = generateTOTP({
      ...this.totpGeneration,
      secret: this.totpGeneration.secret ?? generateSecret(),
    })
    const totpData: TOTPData = { secret, createdAt: Date.now() }

    // https://github.com/panva/jose/blob/main/docs/classes/jwe_compact_encrypt.CompactEncrypt.md
    const jwe = await new jose.CompactEncrypt(
      new TextEncoder().encode(JSON.stringify(totpData)),
    )
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(asJweKey(this.secret))

    const magicLink = generateMagicLink({
      code,
      magicLinkPath: this.magicLinkPath,
      param: this.codeFieldKey,
      request,
    })

    return { code, jwe, magicLink }
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
    sessionTotp: TOTPSessionData
    session: Session
    sessionStorage: SessionStorage
    options: RequiredAuthenticateOptions
  }) {
    try {
      // https://github.com/panva/jose/blob/main/docs/functions/jwe_compact_decrypt.compactDecrypt.md
      const { plaintext } = await jose.compactDecrypt(
        sessionTotp.jwe,
        asJweKey(this.secret),
      )
      const totpData = JSON.parse(new TextDecoder().decode(plaintext))
      assertTOTPData(totpData)

      if (Date.now() - totpData.createdAt > this.totpGeneration.period * 1000) {
        throw new Error(this.customErrors.expiredTotp)
      }
      if (!verifyTOTP({ ...this.totpGeneration, secret: totpData.secret, otp: code })) {
        throw new Error(this.customErrors.invalidTotp)
      }
    } catch (error) {
      if (error instanceof Error && error.message === this.customErrors.expiredTotp) {
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

  private async _readFormData(request: Request, options: AuthenticateOptions) {
    if (request.method !== 'POST') {
      return new FormData()
    }
    if (options.context?.formData instanceof FormData) {
      return options.context.formData
    }
    return await request.formData()
  }
}
