import { generateTOTP, verifyTOTP } from '@epic-web/totp'
import * as jose from 'jose'
import { Cookie, SetCookie } from '@mjackson/headers'

import {
  generateSecret,
  assertTOTPData,
  asJweKey,
  coerceToOptionalNonEmptyString,
  coerceToOptionalString,
  coerceToOptionalTotpSessionData,
} from './utils.js'

import {
  STRATEGY_NAME,
  FORM_FIELDS,
  SESSION_KEYS,
  ERRORS,
} from './constants.js'
import { redirect } from './lib/redirect.js'
import { Strategy } from 'remix-auth/strategy'

export interface TOTPData {
  secret: string
  createdAt: number
}

export interface TOTPSessionData {
  jwe: string
  attempts: number
}

export interface TOTPGenerationOptions {
  secret?: string
  algorithm?: string
  charSet?: string
  digits?: number
  period?: number
  maxAttempts?: number
}

export interface SendTOTPOptions {
  email: string
  code: string
  magicLink: string
  request: Request
  formData: FormData
  context?: unknown
}

export interface SendTOTP {
  (options: SendTOTPOptions): Promise<void>
}

export interface ValidateEmail {
  (email: string): Promise<boolean>
}

export interface CustomErrorsOptions {
  requiredEmail?: string
  invalidEmail?: string
  invalidTotp?: string
  expiredTotp?: string
  missingSessionEmail?: string
}

export interface TOTPStrategyOptions {
  secret: string
  maxAge?: number
  totpGeneration?: TOTPGenerationOptions
  magicLinkPath?: string
  customErrors?: CustomErrorsOptions
  emailFieldKey?: string
  codeFieldKey?: string
  sessionEmailKey?: string
  sessionTotpKey?: string
  sendTOTP: SendTOTP
  validateEmail?: ValidateEmail
  successRedirect: string
  failureRedirect: string
}

export interface TOTPVerifyParams {
  email: string
  formData?: FormData
  request: Request
  context?: unknown
}

/**
 * A simple store that keeps TOTP-related state in a cookie.
 * Stores email, TOTP data, and a possible error message.
 */
class TOTPStore {
  private email?: string
  private totp?: TOTPSessionData
  private error?: { message: string }

  static COOKIE_NAME = '_totp'

  constructor(private cookie: Cookie) {
    const raw = this.cookie.get(TOTPStore.COOKIE_NAME)
    if (raw) {
      const params = new URLSearchParams(raw)
      this.email = params.get('email') || undefined
      const totpRaw = params.get('totp')
      if (totpRaw) {
        try {
          this.totp = JSON.parse(totpRaw)
        } catch {}
      }
      const err = params.get('error')
      if (err) {
        this.error = { message: err }
      }
    }
  }

  static fromRequest(request: Request) {
    return new TOTPStore(new Cookie(request.headers.get('cookie') ?? ''))
  }

  getEmail() {
    return this.email
  }

  getTOTP() {
    return this.totp
  }

  getError() {
    return this.error
  }

  setEmail(email: string | undefined) {
    this.email = email
  }

  setTOTP(totp: TOTPSessionData | undefined) {
    this.totp = totp
  }

  setError(message: string | undefined) {
    if (message) {
      this.error = { message }
    } else {
      this.error = undefined
    }
  }

  commit(): string {
    const params = new URLSearchParams()
    if (this.email) params.set('email', this.email)
    if (this.totp) params.set('totp', JSON.stringify(this.totp))
    if (this.error) params.set('error', this.error.message)
    const setCookie = new SetCookie({
      name: TOTPStore.COOKIE_NAME,
      value: params.toString(),
      httpOnly: true,
      path: '/',
      sameSite: 'Lax',
      secure: true,
    })
    return setCookie.toString()
  }
}

export class TOTPStrategy<User> extends Strategy<User, TOTPVerifyParams> {
  public name = STRATEGY_NAME
  private successRedirect: string
  private failureRedirect: string

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
    algorithm: 'SHA-256',
    charSet: 'abcdefghijklmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ123456789',
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
    this.sessionEmailKey = options.sessionEmailKey ?? SESSION_KEYS.EMAIL
    this.sessionTotpKey = options.sessionTotpKey ?? SESSION_KEYS.TOTP
    this.sendTOTP = options.sendTOTP
    this.validateEmail = options.validateEmail ?? this._validateEmailDefault
    this.successRedirect = options.successRedirect
    this.failureRedirect = options.failureRedirect

    this.totpGeneration = {
      ...this._totpGenerationDefaults,
      ...options.totpGeneration,
    }
    this.customErrors = {
      ...this._customErrorsDefaults,
      ...options.customErrors,
    }
  }
 
  async authenticate(
    request: Request,
  ): Promise<User> {
    if (!this.secret) throw new Error(ERRORS.REQUIRED_ENV_SECRET)
    if (!this.successRedirect) throw new Error(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)
    if (!this.failureRedirect) throw new Error(ERRORS.REQUIRED_FAILURE_REDIRECT_URL)

    // Retrieve the TOTP store from cookies
    const store = TOTPStore.fromRequest(request)

    // If you previously stored a user in session, you'd need a separate cookie or logic.
    // For minimal changes, we assume there's no pre-authenticated user:
    const user: User | null = null
    if (user) return user

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
        const { code, jwe, magicLink } = await this._generateTOTP({ email, request })
        await this.sendTOTP({
          email,
          code,
          magicLink,
          formData,
          request,
        })

        const totpData: TOTPSessionData = { jwe, attempts: 0 }
        store.setEmail(email)
        store.setTOTP(totpData)
        store.setError(undefined)

        throw redirect(this.successRedirect, {
          headers: {
            'Set-Cookie': store.commit(),
          },
        })
      }

      const code = formDataCode ?? this._getMagicLinkCode(request)
      if (code) {
        if (!sessionEmail) throw new Error(this.customErrors.missingSessionEmail)
        if (!sessionTotp) throw new Error(this.customErrors.expiredTotp)
        await this._validateTOTP({ code, sessionTotp, store })

        // Clear TOTP data since user verified successfully
        store.setEmail(undefined)
        store.setTOTP(undefined)
        store.setError(undefined)

        // If you want to store authenticated user, you'd do it with another cookie here
        // e.g. store user session with your own logic

        throw redirect(this.successRedirect, {
          headers: {
            'Set-Cookie': store.commit(),
          },
        })
      }

      throw new Error(this.customErrors.requiredEmail)
    } catch (throwable) {
      if (throwable instanceof Response) throw throwable
      if (throwable instanceof Error) {
        store.setError(throwable.message)
        throw redirect(this.failureRedirect, {
          headers: {
            'Set-Cookie': store.commit(),
          },
        })
      }
      throw throwable
    }
  }

  private async _validateTOTP({
    code,
    sessionTotp,
    store,
  }: {
    code: string
    sessionTotp: TOTPSessionData
    store: TOTPStore
  }) {
    try {
      const { plaintext } = await jose.compactDecrypt(
        sessionTotp.jwe,
        asJweKey(this.secret),
      )
      const totpData = JSON.parse(new TextDecoder().decode(plaintext))
      assertTOTPData(totpData)

      if (Date.now() - totpData.createdAt > this.totpGeneration.period * 1000) {
        throw new Error(this.customErrors.expiredTotp)
      }
      if (!await verifyTOTP({ ...this.totpGeneration, secret: totpData.secret, otp: code })) {
        throw new Error(this.customErrors.invalidTotp)
      }
    } catch (error) {
      if (error instanceof Error && error.message === this.customErrors.expiredTotp) {
        store.setTOTP(undefined)
        store.setError(this.customErrors.expiredTotp)
      } else {
        sessionTotp.attempts += 1
        if (sessionTotp.attempts >= this.totpGeneration.maxAttempts) {
          store.setTOTP(undefined)
        } else {
          store.setTOTP(sessionTotp)
        }
        store.setError(this.customErrors.invalidTotp)
      }
      throw redirect(this.failureRedirect, {
        headers: {
          'Set-Cookie': store.commit(),
        },
      })
    }
  }

  private async _readFormData(request: Request) {
    if (request.method !== 'POST') {
      return new FormData()
    }
    return await request.formData()
  }

  private async _generateTOTP({ email, request }: { email: string; request: Request }) {
    const isValidEmail = await this.validateEmail(email)
    if (!isValidEmail) throw new Error(this.customErrors.invalidEmail)

    const { otp: code, secret } = await generateTOTP({
      ...this.totpGeneration,
      secret: this.totpGeneration.secret ?? generateSecret(),
    })
    const totpData = { secret, createdAt: Date.now() }

    const jwe = await new jose.CompactEncrypt(
      new TextEncoder().encode(JSON.stringify(totpData)),
    )
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(asJweKey(this.secret))

    const magicLink = this._generateMagicLink({ code, request })
    return { code, jwe, magicLink }
  }

  private _generateMagicLink({ code, request }: { code: string; request: Request }) {
    const url = new URL(this.magicLinkPath ?? '/', new URL(request.url).origin)
    url.searchParams.set(this.codeFieldKey, code)
    return url.toString()
  }

  private async _validateEmailDefault(email: string) {
    const regexEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/gm
    return regexEmail.test(email)
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
}
