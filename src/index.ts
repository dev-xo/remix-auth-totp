import { Strategy } from 'remix-auth/strategy'
import { generateTOTP, verifyTOTP } from '@epic-web/totp'
import { Cookie, SetCookie } from '@mjackson/headers'
import * as jose from 'jose'
import { redirect } from './utils.js'
import {
  generateSecret,
  coerceToOptionalString,
  coerceToOptionalTotpSessionData,
  coerceToOptionalNonEmptyString,
  assertTOTPData,
  asJweKey,
} from './utils.js'
import { STRATEGY_NAME, FORM_FIELDS, ERRORS } from './constants.js'

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
 * The TOTP data stored in the cookie.
 */
export interface TOTPCookieData {
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

  /**
   * The missing session email error message.
   */
  missingSessionEmail?: string
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
   * The send TOTP method.
   */
  sendTOTP: SendTOTP

  /**
   * The validate email method.
   */
  validateEmail?: ValidateEmail

  /**
   * The redirect URL thrown after sending email.
   */
  emailSentRedirect: string

  /**
   * The redirect URL thrown after verification success.
   */
  successRedirect: string

  /**
   * The redirect URL thrown after verification failure.
   */
  failureRedirect: string
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

/**
 * A store class that manages TOTP-related state in a cookie.
 * Handles email, TOTP session data, and error messages.
 */
class TOTPStore {
  private email?: string
  private totp?: TOTPCookieData
  private error?: { message: string }

  /** The name of the cookie used to store TOTP data. */
  static COOKIE_NAME = '_totp'

  /**
   * Creates a new TOTPStore instance.
   * @param cookie - The Cookie instance used to manage cookie data.
   */
  constructor(private cookie: Cookie) {
    const raw = this.cookie.get(TOTPStore.COOKIE_NAME)
    if (raw) {
      const params = new URLSearchParams(raw)
      this.email = params.get('email') || undefined

      const totpRaw = params.get('totp')
      if (totpRaw) {
        try {
          this.totp = JSON.parse(totpRaw)
        } catch {
          // Silently handle invalid JSON in the TOTP data.
        }
      }

      const err = params.get('error')
      if (err) {
        this.error = { message: err }
      }
    }
  }

  /**
   * Creates a TOTPStore instance from a Request object.
   * @param request - The incoming request object.
   * @returns A new TOTPStore instance.
   */
  static fromRequest(request: Request): TOTPStore {
    return new TOTPStore(new Cookie(request.headers.get('cookie') ?? ''))
  }

  /**
   * Gets the stored email address.
   * @returns The email address or undefined if not set.
   */
  getEmail(): string | undefined {
    return this.email
  }

  /**
   * Gets the stored TOTP session data.
   * @returns The TOTP session data or undefined if not set.
   */
  getTOTP(): TOTPCookieData | undefined {
    return this.totp
  }

  /**
   * Gets the stored error message.
   * @returns The error object or undefined if no error exists.
   */
  getError(): { message: string } | undefined {
    return this.error
  }

  /**
   * Sets the email address in the store.
   * @param email - The email address to store or undefined to clear it.
   */
  setEmail(email: string | undefined): void {
    this.email = email
  }

  /**
   * Sets the TOTP session data in the store.
   * @param totp - The TOTP session data to store or undefined to clear it.
   */
  setTOTP(totp: TOTPCookieData | undefined): void {
    this.totp = totp
  }

  /**
   * Sets an error message in the store.
   * @param message - The error message to store or undefined to clear it.
   */
  setError(message: string | undefined): void {
    if (message) {
      this.error = { message }
    } else {
      this.error = undefined
    }
  }

  /**
   * Commits the current store state to a cookie string.
   * @param maxAge - Optional maximum age of the cookie in seconds
   * @returns A string representation of the cookie with all current values
   */
  commit(maxAge?: number): string {
    const params = new URLSearchParams()

    if (this.email) {
      params.set('email', this.email)
    }

    if (this.totp) {
      params.set('totp', JSON.stringify(this.totp))
    }

    if (this.error) {
      params.set('error', this.error.message)
    }

    const setCookie = new SetCookie({
      name: TOTPStore.COOKIE_NAME,
      value: params.toString(),
      httpOnly: true,
      secure: true,
      path: '/',
      sameSite: 'Lax',
      maxAge: maxAge,
    })

    return setCookie.toString()
  }
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
  private readonly sendTOTP: SendTOTP
  private readonly validateEmail: ValidateEmail
  private _emailSentRedirect: string
  private _successRedirect: string
  private _failureRedirect: string
  private readonly _totpGenerationDefaults = {
    algorithm: 'SHA-256', // More secure than SHA1.
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
    missingSessionEmail: ERRORS.MISSING_SESSION_EMAIL,
  }

  constructor(
    options: TOTPStrategyOptions,
    verify: Strategy.VerifyFunction<User, TOTPVerifyParams>,
  ) {
    super(verify)
    this.secret = options.secret
    this.maxAge = options.maxAge
    this.magicLinkPath = options.magicLinkPath ?? '/magic-link'
    this.emailFieldKey = options.emailFieldKey ?? FORM_FIELDS.EMAIL
    this.codeFieldKey = options.codeFieldKey ?? FORM_FIELDS.CODE
    this.sendTOTP = options.sendTOTP
    this.validateEmail = options.validateEmail ?? this._validateEmailDefault
    this._emailSentRedirect = options.emailSentRedirect
    this._successRedirect = options.successRedirect
    this._failureRedirect = options.failureRedirect
    this.totpGeneration = {
      ...this._totpGenerationDefaults,
      ...options.totpGeneration,
    }
    this.customErrors = {
      ...this._customErrorsDefaults,
      ...options.customErrors,
    }
  }

  // Getter for emailSentRedirect
  get emailSentRedirect(): string {
    return this._emailSentRedirect
  }

  // Setter for emailSentRedirect
  set emailSentRedirect(url: string) {
    if (!url) {
      throw new Error(ERRORS.REQUIRED_EMAIL_SENT_REDIRECT_URL)
    }
    this._emailSentRedirect = url
  }

  // Getter for successRedirect
  get successRedirect(): string {
    return this._successRedirect
  }

  // Setter for successRedirect
  set successRedirect(url: string) {
    if (!url) {
      throw new Error(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)
    }
    this._successRedirect = url
  }

  // Getter for failureRedirect
  get failureRedirect(): string {
    return this._failureRedirect
  }

  // Setter for failureRedirect
  set failureRedirect(url: string) {
    if (!url) {
      throw new Error(ERRORS.REQUIRED_FAILURE_REDIRECT_URL)
    }
    this._failureRedirect = url
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
  async authenticate(request: Request): Promise<User> {
    if (!this.secret) throw new Error(ERRORS.REQUIRED_ENV_SECRET)
    if (!this._emailSentRedirect) throw new Error(ERRORS.REQUIRED_EMAIL_SENT_REDIRECT_URL)
    if (!this._successRedirect) throw new Error(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)
    if (!this._failureRedirect) throw new Error(ERRORS.REQUIRED_FAILURE_REDIRECT_URL)

    // Retrieve the TOTP store from request.
    const store = TOTPStore.fromRequest(request)

    const formData = await this._readFormData(request)
    const formDataEmail = coerceToOptionalNonEmptyString(formData.get(this.emailFieldKey))
    const formDataCode = coerceToOptionalNonEmptyString(formData.get(this.codeFieldKey))
    const sessionEmail = coerceToOptionalString(store.getEmail())
    const sessionTotp = coerceToOptionalTotpSessionData(store.getTOTP())
    const email =
      request.method === 'POST'
        ? formDataEmail ?? (!formDataCode ? sessionEmail : null)
        : null

    try {
      if (email) {
        // Generate the TOTP.
        const { code, jwe, magicLink } = await this._generateTOTP({ email, request })

        // Send the TOTP to the user.
        await this.sendTOTP({
          email,
          code,
          magicLink,
          formData,
          request,
        })

        const totpData: TOTPCookieData = { jwe, attempts: 0 }
        store.setEmail(email)
        store.setTOTP(totpData)
        store.setError(undefined)

        throw redirect(this._emailSentRedirect, {
          headers: {
            'Set-Cookie': store.commit(this.maxAge),
          },
        })
      }

      // Get the TOTP code, either from form data or magic link.
      const code = formDataCode ?? this._getMagicLinkCode(request)

      if (code) {
        if (!sessionEmail) throw new Error(this.customErrors.missingSessionEmail)
        if (!sessionTotp) throw new Error(this.customErrors.expiredTotp)

        // Validate the TOTP.
        await this._validateTOTP({ code, sessionTotp, store })

        // Clear TOTP data since user verified successfully.
        store.setEmail(undefined)
        store.setTOTP(undefined)
        store.setError(undefined)

        await this.verify({ email: sessionEmail, formData, request })

        throw redirect(this._successRedirect, {
          headers: {
            'Set-Cookie': store.commit(this.maxAge),
          },
        })
      }
      throw new Error(this.customErrors.requiredEmail)
    } catch (err: unknown) {
      if (err instanceof Response) {
        const headers = new Headers(err.headers)
        headers.append('Set-Cookie', store.commit(this.maxAge))
        throw new Response(err.body, {
          status: err.status,
          headers: headers,
          statusText: err.statusText,
        })
      }
      if (err instanceof Error) {
        store.setError(err.message)
        throw redirect(this._failureRedirect, {
          headers: {
            'Set-Cookie': store.commit(this.maxAge),
          },
        })
      }
      throw err
    }
  }

  /**
   * Reads the form data from the request.
   * @param request - The request object.
   * @returns The form data.
   */
  private async _readFormData(request: Request) {
    if (request.method !== 'POST') {
      return new FormData()
    }
    return await request.formData()
  }

  /**
   * Validates the TOTP.
   * @param code - The TOTP code.
   * @param sessionTotp - The TOTP session data.
   * @param store - The TOTP store.
   */
  private async _validateTOTP({
    code,
    sessionTotp,
    store,
  }: {
    code: string
    sessionTotp: TOTPCookieData
    store: TOTPStore
  }) {
    try {
      // https://github.com/panva/jose/blob/main/docs/functions/jwe_compact_decrypt.compactDecrypt.md
      const { plaintext } = await jose.compactDecrypt(
        sessionTotp.jwe,
        asJweKey(this.secret),
      )
      const totpData = JSON.parse(new TextDecoder().decode(plaintext))
      assertTOTPData(totpData)

      // Check if the TOTP is expired.
      const dateNow = Date.now()
      const isExpired = dateNow - totpData.createdAt > this.totpGeneration.period * 1000
      if (isExpired) {
        throw new Error(this.customErrors.expiredTotp)
      }

      // Check if the TOTP is valid.
      const isValid = await verifyTOTP({
        ...this.totpGeneration,
        secret: totpData.secret,
        otp: code,
      })
      if (!isValid) {
        throw new Error(this.customErrors.invalidTotp)
      }
    } catch (error) {
      if (error instanceof Error && error.message === this.customErrors.expiredTotp) {
        store.setTOTP(undefined)
        store.setError(this.customErrors.expiredTotp)
      } else {
        sessionTotp.attempts += 1
        // Check if the user has reached the max number of attempts.
        if (sessionTotp.attempts >= this.totpGeneration.maxAttempts) {
          store.setTOTP(undefined)
        } else {
          store.setTOTP(sessionTotp)
        }
        store.setError(this.customErrors.invalidTotp)
      }

      // Redirect to the failure URL with the updated store.
      throw redirect(this._failureRedirect, {
        headers: {
          'Set-Cookie': store.commit(this.maxAge),
        },
      })
    }
  }

  /**
   * Generates the TOTP.
   * @param email - The email address.
   * @param request - The request object.
   * @returns The TOTP data.
   */
  private async _generateTOTP({ email, request }: { email: string; request: Request }) {
    const isValidEmail = await this.validateEmail(email)
    if (!isValidEmail) throw new Error(this.customErrors.invalidEmail)

    const { otp: code, secret } = await generateTOTP({
      ...this.totpGeneration,
      secret: this.totpGeneration.secret ?? generateSecret(),
    })
    const totpData: TOTPData = { secret, createdAt: Date.now() }

    const jwe = await new jose.CompactEncrypt(
      new TextEncoder().encode(JSON.stringify(totpData)),
    )
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(asJweKey(this.secret))

    const magicLink = this._generateMagicLink({ code, request })

    return {
      code,
      jwe,
      magicLink,
    }
  }

  /**
   * Generates the magic link.
   * @param code - The TOTP code.
   * @param request - The request object.
   * @returns The magic link.
   */
  private _generateMagicLink({ code, request }: { code: string; request: Request }) {
    const url = new URL(this.magicLinkPath ?? '/', new URL(request.url).origin)
    url.searchParams.set(this.codeFieldKey, code)
    return url.toString()
  }

  /**
   * Gets the magic link code from the request.
   * @param request - The request object.
   * @returns The magic link code.
   */
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

  /**
   * Validates the email format.
   * @param email - The email address.
   * @returns Whether the email is valid.
   */
  private async _validateEmailDefault(email: string) {
    const regexEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/gm
    return regexEmail.test(email)
  }
}
