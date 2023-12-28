import type { SessionStorage } from '@remix-run/server-runtime'
import type { AuthenticateOptions, StrategyVerifyCallback } from 'remix-auth'

import { redirect } from '@remix-run/server-runtime'
import { Strategy } from 'remix-auth'
import { verifyTOTP } from '@epic-web/totp'
import {
  generateSecret,
  generateTOTP,
  generateMagicLink,
  signJWT,
  verifyJWT,
} from './utils.js'
import { STRATEGY_NAME, FORM_FIELDS, SESSION_KEYS, ERRORS } from './constants.js'

/**
 * The TOTP data the application stores.
 * Used in CRUD functions provided by the application.
 */
export interface TOTPData {
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
 * The create TOTP CRUD method.
 *
 * @param data The TOTP data.
 * @param expiresAt The TOTP expiration date.
 */
export interface CreateTOTP {
  (data: TOTPData, expiresAt: Date): Promise<void>
}

/**
 * The read TOTP CRUD method.
 *  @param hash The hash of the TOTP.
 */
export interface ReadTOTP {
  (hash: string): Promise<TOTPData | null>
}

/**
 * The update TOTP CRUD method.
 *
 * @param hash The hash of the TOTP.
 * @param data The TOTP data to be updated.
 * @param expiresAt The TOTP expiration date. It is always the same as the expiration passed into createTOTP().
 */
export interface UpdateTOTP {
  (hash: string, data: Partial<Omit<TOTPData, 'hash'>>, expiresAt: Date): Promise<void>
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
   * The create TOTP method.
   */
  createTOTP: CreateTOTP

  /**
   * The read TOTP method.
   */
  readTOTP: ReadTOTP

  /**
   * The update TOTP method.
   */
  updateTOTP: UpdateTOTP

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

  /**
   * The session key that stores flag that first otp has been requested.
   * @default "auth:firstOtpRequested"
   */
  sessionFirstOTPRequestedKey?: string
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
  private readonly createTOTP: CreateTOTP
  private readonly readTOTP: ReadTOTP
  private readonly updateTOTP: UpdateTOTP
  private readonly sendTOTP: SendTOTP
  private readonly validateEmail: ValidateEmail
  private readonly customErrors: CustomErrorsOptions
  private readonly emailFieldKey: string
  private readonly totpFieldKey: string
  private readonly sessionEmailKey: string
  private readonly sessionTotpKey: string
  private readonly sessionTotpExpiresAtKey: string
  private readonly sessionFirstOTPRequestedKey: string

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
    this.createTOTP = options.createTOTP
    this.readTOTP = options.readTOTP
    this.updateTOTP = options.updateTOTP
    this.sendTOTP = options.sendTOTP
    this.validateEmail = options.validateEmail ?? this._validateEmailDefaults
    this.emailFieldKey = options.emailFieldKey ?? FORM_FIELDS.EMAIL
    this.totpFieldKey = options.totpFieldKey ?? FORM_FIELDS.TOTP
    this.sessionEmailKey = options.sessionEmailKey ?? SESSION_KEYS.EMAIL
    this.sessionTotpKey = options.sessionTotpKey ?? SESSION_KEYS.TOTP
    this.sessionTotpExpiresAtKey =
      options.sessionTotpExpiresAtKey ?? SESSION_KEYS.TOTP_EXPIRES_AT
    this.sessionFirstOTPRequestedKey = SESSION_KEYS.FIRST_OTP_REQUESTED

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

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions,
  ): Promise<User> {
    if (!this.secret) throw new Error(ERRORS.REQUIRED_ENV_SECRET)
    if (!options.successRedirect) throw new Error(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)

    const isPOST = request.method === 'POST'
    const isGET = request.method === 'GET'

    const session = await sessionStorage.getSession(request.headers.get('cookie'))
    const sessionEmail = session.get(this.sessionEmailKey)
    const sessionTotp = session.get(this.sessionTotpKey)
    const sessionTotpExpiresAt = session.get(this.sessionTotpExpiresAtKey)
    const sessionFirstOtpRequested = session.get(SESSION_KEYS.FIRST_OTP_REQUESTED)

    let user: User | null = session.get(options.sessionKey) ?? null

    let formData: FormData | undefined = undefined
    let formDataEmail: string | undefined = undefined
    let formDataTotp: string | undefined = undefined
    let magicLinkTotp: string | undefined = undefined

    try {
      if (!user) {
        /**
         * 1st Authentication Phase.
         */
        if (isPOST) {
          formData = await request.formData()
          const form = Object.fromEntries(formData)

          formDataEmail = form[this.emailFieldKey] && String(form[this.emailFieldKey])
          formDataTotp = form[this.totpFieldKey] && String(form[this.totpFieldKey])

          /**
           * Re-send TOTP - User has requested a new TOTP.
           * This will invalidate previous TOTP and assign session email to form email.
           */
          if (
            !formDataEmail &&
            !formDataTotp &&
            sessionEmail &&
            sessionTotp &&
            sessionTotpExpiresAt
          ) {
            const expiresAt = new Date(sessionTotpExpiresAt)
            await this.updateTOTP(sessionTotp, { active: false }, expiresAt)
            formDataEmail = sessionEmail
          }

          /**
           * Invalidate previous TOTP - User has submitted a new email address.
           */
          if (
            formDataEmail &&
            sessionEmail &&
            formDataEmail !== sessionEmail &&
            sessionTotp &&
            sessionTotpExpiresAt
          ) {
            const expiresAt = new Date(sessionTotpExpiresAt)
            await this.updateTOTP(sessionTotp, { active: false }, expiresAt)
            session.unset(this.sessionFirstOTPRequestedKey)
          }

          /**
           * First TOTP request.
           */
          if (!formDataTotp) {
            if (!formDataEmail) throw new Error(this.customErrors.requiredEmail)
            await this.validateEmail(formDataEmail)

            // Generate, Sign and create Magic Link.
            const { otp: _otp, ...totp } = generateTOTP({
              ...this.totpGeneration,
              secret: generateSecret(),
            })
            const signedTotp = await signJWT({
              payload: totp,
              expiresIn:
                this.totpGeneration.period ?? this._totpGenerationDefaults.period,
              secretKey: this.secret,
            })
            const magicLink = generateMagicLink({
              ...this.magicLinkGeneration,
              param: this.totpFieldKey,
              code: _otp,
              request,
            })

            // Create TOTP in application storage. (Milliseconds since Unix epoch).
            const expiresAtEpochMs =
              Date.now() + (totp.period ?? this._totpGenerationDefaults.period) * 1000
            const expiresAt = new Date(expiresAtEpochMs)

            await this.createTOTP(
              { hash: signedTotp, active: true, attempts: 0 },
              expiresAt,
            )

            // Send TOTP.
            await this.sendTOTP({
              email: formDataEmail,
              code: _otp,
              magicLink,
              form: formData,
              request,
            })

            if(sessionFirstOtpRequested) {
              session.flash(SESSION_KEYS.OTP_RESENT, "OTP Has been resent")
            }

            session.set(this.sessionEmailKey, formDataEmail)
            session.set(this.sessionTotpKey, signedTotp)
            session.set(this.sessionTotpExpiresAtKey, expiresAt.toISOString())

            if (!sessionFirstOtpRequested) {
              session.set(this.sessionFirstOTPRequestedKey, 'true')
            }
            session.unset(options.sessionErrorKey)

            throw redirect(options.successRedirect, {
              headers: {
                'set-cookie': await sessionStorage.commitSession(session, {
                  maxAge: this.maxAge,
                }),
              },
            })
          }
        }

        /**
         * 2nd Authentication Phase.
         * Either via form submission or magic-link URL.
         */
        if (isGET && this.magicLinkGeneration.enabled) {
          const url = new URL(request.url)

          if (url.pathname !== this.magicLinkGeneration.callbackPath) {
            throw new Error(ERRORS.INVALID_MAGIC_LINK_PATH)
          }

          magicLinkTotp = url.searchParams.has(this.totpFieldKey)
            ? decodeURIComponent(url.searchParams.get(this.totpFieldKey) ?? '')
            : undefined
        }

        if ((isPOST && formDataTotp) || (isGET && magicLinkTotp)) {
          // Validation.
          const expiresAt = new Date(sessionTotpExpiresAt)
          if (isPOST && formDataTotp)
            await this._validateTOTP(sessionTotp, formDataTotp, expiresAt)
          if (isGET && magicLinkTotp)
            await this._validateTOTP(sessionTotp, magicLinkTotp, expiresAt)

          // Invalidation.
          await this.updateTOTP(sessionTotp, { active: false }, expiresAt)

          // Allow developer to handle user validation.
          user = await this.verify({
            email: sessionEmail,
            form: formData,
            magicLink: magicLinkTotp,
            request,
          })

          session.set(options.sessionKey, user)
          session.unset(this.sessionEmailKey)
          session.unset(this.sessionTotpKey)
          session.unset(this.sessionTotpExpiresAtKey)
          session.unset(options.sessionErrorKey)

          throw redirect(options.successRedirect, {
            headers: {
              'set-cookie': await sessionStorage.commitSession(session, {
                maxAge: this.maxAge,
              }),
            },
          })
        }
      }
    } catch (error) {
      // Allow Response to pass-through.
      if (error instanceof Response && error.status === 302) throw error
      if (error instanceof Error) {
        if (error.message === ERRORS.INVALID_JWT) {
          const dbTOTP = await this.readTOTP(sessionTotp)
          if (!dbTOTP || !dbTOTP.hash) throw new Error(this.customErrors.totpNotFound)

          const expiresAt = new Date(sessionTotpExpiresAt)
          await this.updateTOTP(sessionTotp, { active: false }, expiresAt)

          return await this.failure(
            this.customErrors.inactiveTotp || ERRORS.INACTIVE_TOTP,
            request,
            sessionStorage,
            options,
            error,
          )
        }

        return await this.failure(error.message, request, sessionStorage, options, error)
      }
      if (typeof error === 'string') {
        return await this.failure(
          error,
          request,
          sessionStorage,
          options,
          new Error(error),
        )
      }
      return await this.failure(
        ERRORS.UNKNOWN_ERROR,
        request,
        sessionStorage,
        options,
        new Error(JSON.stringify(error, null, 2)),
      )
    }

    if (!user) throw new Error(ERRORS.USER_NOT_FOUND)

    return this.success(user, request, sessionStorage, options)
  }

  private async _validateEmailDefaults(email: string) {
    const regexEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/gm
    if (!regexEmail.test(email)) throw new Error(this.customErrors.invalidEmail)
  }

  private async _validateTOTP(sessionTotp: string, otp: string, expiresAt: Date) {
    // Retrieve encrypted TOTP from database.
    const dbTOTP = await this.readTOTP(sessionTotp)
    if (!dbTOTP || !dbTOTP.hash) throw new Error(this.customErrors.totpNotFound)

    if (dbTOTP.active !== true) {
      throw new Error(this.customErrors.inactiveTotp)
    }

    const maxAttempts =
      this.totpGeneration.maxAttempts ?? this._totpGenerationDefaults.maxAttempts

    if (dbTOTP.attempts >= maxAttempts) {
      await this.updateTOTP(sessionTotp, { active: false }, expiresAt)
      throw new Error(this.customErrors.inactiveTotp)
    }

    // Decryption and Verification.
    const { ...totp } = (await verifyJWT({
      jwt: sessionTotp,
      secretKey: this.secret,
    })) as Required<TOTPGenerationOptions>

    // Verify TOTP (@epic-web/totp).
    const isValid = verifyTOTP({ ...totp, otp })
    if (!isValid) {
      await this.updateTOTP(sessionTotp, { attempts: dbTOTP.attempts + 1 }, expiresAt)
      throw new Error(this.customErrors.invalidTotp)
    }
  }
}
