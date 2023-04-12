import type { SessionStorage } from '@remix-run/server-runtime'
import type { AuthenticateOptions, StrategyVerifyCallback } from 'remix-auth'

import { redirect } from '@remix-run/server-runtime'
import { Strategy } from 'remix-auth'
import { encrypt, decrypt, generateOtp, generateMagicLink } from './utils'

/**
 * A function that validates the email address.
 * This can be useful to ensure it's not a disposable email address.
 *
 * @param email The email address to validate.
 */
export interface ValidateEmailFunction {
  (email: string): Promise<void>
}

/**
 * The code generation configuration.
 */
export interface CodeGenerationOptions {
  /**
   * How long the OTP code will be valid.
   * @default 900000 Default is 15 minutes in milliseconds. (1000 * 60 * 15)
   */
  expiresAt?: number

  /**
   * How many times an invalid OTP code can be inputted.
   * @default 3
   */
  maxAttempts?: number

  /**
   * How long the OTP code will be in length.
   * @default 6
   */
  length?: number

  /**
   * Whether the OTP code should contain digits.
   * @default false
   */
  digits?: boolean

  /**
   * Whether the OTP code should contain lower case alphabets.
   * @default false
   */
  lowerCaseAlphabets?: boolean

  /**
   * Whether the OTP code should contain upper case alphabets.
   * @default true
   */
  upperCaseAlphabets?: boolean

  /**
   * Whether the OTP code should contain special characters.
   * @default false
   */
  specialChars?: boolean
}

/**
 * The Magic Link configuration.
 */
export interface MagicLinkGenerationOptions {
  /**
   * Whether to enable the Magic Link feature.
   * @default true
   */
  enabled?: boolean

  /**
   * The base URL for building the Magic Link URL.
   * If omitted, the baseUrl will be inferred from the request.
   * @default undefined
   */
  baseUrl?: string

  /**
   * The path for the Magic Link callback.
   * @default '/magic-link'
   */
  callbackPath?: string
}

/**
 * A function that stores the OTP code into database.
 * @param code The encrypted OTP code.
 */
export interface StoreCodeFunction {
  (code: string): Promise<void>
}

/**
 * The send code configuration.
 */
export interface SendCodeOptions<User> {
  /**
   * The email address provided by the user.
   */
  email: string

  /**
   * The decrypted OTP code.
   */
  code: string

  /**
   * The Magic Link URL.
   */
  magicLink?: string

  /**
   * The user object.
   */
  user?: User | null

  /**
   * The formData object.
   */
  form?: FormData

  /**
   * The request object.
   */
  request: Request
}

/**
 * The sender email function.
 * @param options The send code options.
 */
export interface SendCodeFunction<User> {
  (options: SendCodeOptions<User>): Promise<void>
}

/**
 * The validate code function.
 * @param code The encrypted OTP code.
 */
export interface ValidateCodeFunction {
  (code: string): Promise<{ code: string; active: boolean; attempts: number }>
}

/**
 * The invalidate code function.
 * @param code The encrypted OTP code.
 * @param active Whether the code is still active.
 * @param attempts The number of attempts inputted.
 */
export interface InvalidateCodeFunction {
  (code: string, active?: boolean, attempts?: number): Promise<void>
}

/**
 * The custom errors configuration.
 */
export interface CustomErrorsOptions {
  /**
   * The error message when the email address is required.
   */
  requiredEmail?: string

  /**
   * The error message when the email address is invalid.
   */
  invalidEmail?: string

  /**
   * The error message when the email address is no longer active.
   */
  inactiveCode?: string

  /**
   * The error message when the OTP code has expired.
   */
  expiredCode?: string

  /**
   * The error message when the OTP code attempts has reached the maximum.
   */
  maxCodeAttemptsReached?: string
}

/**
 * Declares the Strategy configuration
 * needed for the developer to correctly work with.
 */
export interface OTPStrategyOptions<User> {
  /**
   * A secret string used to encrypt and decrypt the OTP code.
   * @default ''
   */
  secret?: string

  /**
   * The form input name used to get the email address.
   * @default "email"
   */
  emailField?: string

  /**
   * The form input name used to get the OTP code.
   * @default "code"
   */
  codeField?: string

  /**
   * The maximum age of the session in milliseconds. (remember me)
   * @default undefined
   */
  maxAge?: number

  /**
   * The validate email function.
   */
  validateEmail?: ValidateEmailFunction

  /**
   * The code generation configuration.
   */
  codeGeneration?: CodeGenerationOptions

  /**
   * The Magic Link configuration.
   */
  magicLinkGeneration?: MagicLinkGenerationOptions

  /**
   * The store code function.
   */
  storeCode: StoreCodeFunction

  /**
   * The send code function.
   */
  sendCode: SendCodeFunction<User>

  /**
   * The validate code function.
   */
  validateCode: ValidateCodeFunction

  /**
   * The invalidate code function.
   */
  invalidateCode: InvalidateCodeFunction

  /**
   * The custom errors configuration.
   */
  customErrors?: CustomErrorsOptions

  /**
   * A Session key that stores the email address.
   * @default "auth:email"
   */
  sessionEmailKey?: string

  /**
   * A Session key that stores the encrypted OTP code.
   * @default "auth:code"
   */
  sessionOtpKey?: string
}

/**
 * Declares the Strategy return data needed for the developer
 * to verify the user identity in their system.
 */
export interface OTPVerifyParams {
  /**
   * The email address provided by the user.
   */
  email: string

  /**
   * The encrypted or decrypted OTP code.
   */
  code?: string

  /**
   * The Magic Link URL used to trigger the authentication.
   */
  magicLink?: string

  /**
   * A FormData object that contains the form
   * used to trigger the authentication.
   */
  form?: FormData

  /**
   * The Request object.
   */
  request: Request
}

export class OTPStrategy<User> extends Strategy<User, OTPVerifyParams> {
  public name = 'OTP'

  private readonly secret: string
  private readonly emailField: string
  private readonly codeField: string
  private readonly maxAge: number | undefined
  private readonly validateEmail: ValidateEmailFunction
  private readonly codeGeneration: CodeGenerationOptions
  private readonly magicLinkGeneration: MagicLinkGenerationOptions
  private readonly storeCode: StoreCodeFunction
  private readonly sendCode: SendCodeFunction<User>
  private readonly validateCode: ValidateCodeFunction
  private readonly invalidateCode: InvalidateCodeFunction
  private readonly customErrors: CustomErrorsOptions
  private readonly sessionEmailKey: string
  private readonly sessionOtpKey: string

  private readonly codeGenerationDefaults = {
    expiresAt: 1000 * 60 * 15,
    maxAttempts: 3,
    length: 6,
    digits: false,
    specialChars: false,
    lowerCaseAlphabets: false,
    upperCaseAlphabets: true,
  }
  private readonly magicLinkGenerationDefaults = {
    enabled: true,
    baseUrl: undefined,
    callbackPath: '/magic-link',
  }
  private readonly customErrorsDefaults = {
    requiredEmail: 'Email address is required.',
    invalidEmail: 'Email address is not valid.',
    inactiveCode: 'Code is no longer active.',
    expiredCode: 'Code has expired.',
    maxCodeAttemptsReached: 'Code cannot be used anymore.',
  }

  constructor(
    options: OTPStrategyOptions<User>,
    verify: StrategyVerifyCallback<User, OTPVerifyParams>,
  ) {
    super(verify)
    this.secret = options.secret ?? ''
    this.emailField = options.emailField ?? 'email'
    this.codeField = options.codeField ?? 'code'
    this.maxAge = options.maxAge ?? undefined
    this.validateEmail = options.validateEmail ?? this.validateEmailDefaults
    this.storeCode = options.storeCode
    this.sendCode = options.sendCode
    this.validateCode = options.validateCode
    this.invalidateCode = options.invalidateCode
    this.sessionEmailKey = options.sessionEmailKey ?? 'auth:email'
    this.sessionOtpKey = options.sessionOtpKey ?? 'auth:otp'

    this.codeGeneration = {
      ...this.codeGenerationDefaults,
      ...options.codeGeneration,
    }
    this.magicLinkGeneration = {
      ...this.magicLinkGenerationDefaults,
      ...options.magicLinkGeneration,
    }
    this.customErrors = {
      ...this.customErrorsDefaults,
      ...options.customErrors,
    }
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions,
  ): Promise<User> {
    if (!this.secret) {
      throw new Error(
        'Missing required `secret` option from OTPStrategy constructor.',
      )
    }

    const isPost = request.method === 'POST'
    const isGet = request.method === 'GET'

    const session = await sessionStorage.getSession(request.headers.get('Cookie'))
    const sessionEmail = session.get(this.sessionEmailKey)
    const sessionOtpEncrypted = session.get(this.sessionOtpKey)

    let user: User | null = session.get(options.sessionKey) ?? null

    try {
      if (!user) {
        let email: string | undefined
        let code: string | undefined
        let magicLink: string | undefined
        let formData: FormData | undefined

        if (!options.successRedirect) {
          throw new Error('Missing required `successRedirect` property.')
        }

        // 1st Authentication phase.
        if (isPost) {
          formData = await request.formData()
          const form = Object.fromEntries(formData)

          email = form[this.emailField] && String(form[this.emailField])
          code = form[this.codeField] && String(form[this.codeField])

          // Request a new OTP code.
          if (!code && sessionEmail && sessionOtpEncrypted) {
            // Invalidate previous OTP code.
            await this.invalidateOtp(sessionOtpEncrypted, false)

            // Re-assign email. Required for OTP code generation.
            email = sessionEmail
          }

          if (!code) {
            if (!email) {
              throw new Error(this.customErrors.requiredEmail)
            }
            await this.validateEmail(email)

            // Generate and encrypt the OTP code.
            const otp = generateOtp({ ...this.codeGeneration })
            const otpEncrypted = await encrypt(
              JSON.stringify({ email, ...otp }),
              this.secret,
            )
            const magicLink = generateMagicLink({
              ...this.magicLinkGeneration,
              param: this.codeField,
              code: otpEncrypted,
              request,
            })

            // Store and send the OTP code.
            await this.saveOtp(otpEncrypted)
            await this.sendOtp(email, otp.code, magicLink, formData, request)

            session.set(this.sessionEmailKey, email)
            session.set(this.sessionOtpKey, otpEncrypted)
            session.unset(options.sessionErrorKey)

            throw redirect(options.successRedirect, {
              headers: {
                'Set-Cookie': await sessionStorage.commitSession(session, {
                  maxAge: this.maxAge,
                }),
              },
            })
          }
        }

        // 2nd Authentication phase.
        // Either via Magic Link or OTP code submission.
        if (isGet && this.magicLinkGeneration.enabled) {
          const url = new URL(request.url)

          if (url.pathname !== this.magicLinkGeneration.callbackPath) {
            throw new Error('Magic Link does not match the expected path.')
          }

          magicLink = decodeURIComponent(url.searchParams.get(this.codeField) ?? '')
        }

        if ((isPost && code) || (isGet && magicLink)) {
          if (!session.has(this.sessionEmailKey)) {
            throw new Error('Missing required email address.')
          }
          if (!session.has(this.sessionOtpKey)) {
            throw new Error('Missing required OTP code.')
          }

          // Handle validations.
          if (isPost && code) {
            await this.validateOtp(code, sessionOtpEncrypted)
          }
          if (isGet && magicLink) {
            await this.validateMagicLink(magicLink, sessionOtpEncrypted)
          }

          // Handle invalidations.
          await this.invalidateOtp(sessionOtpEncrypted, false)

          // Get and Set user data.
          user = await this.verify({
            email: sessionEmail,
            form: formData,
            magicLink,
            request,
          })

          session.set(options.sessionKey, user)
          session.unset(this.sessionEmailKey)
          session.unset(this.sessionOtpKey)
          session.unset(options.sessionErrorKey)

          throw redirect(options.successRedirect, {
            headers: {
              'Set-Cookie': await sessionStorage.commitSession(session, {
                maxAge: this.maxAge,
              }),
            },
          })
        }
      }
    } catch (error) {
      if (error instanceof Response && error.status === 302) {
        throw error
      }

      if (error instanceof Error) {
        if (error.message === 'Code has reached maximum attempts.') {
          // Invalidate maximum attempted OTP code.
          const sessionOtpEncrypted = session.get(this.sessionOtpKey)
          await this.invalidateOtp(sessionOtpEncrypted, false)
        }

        return await this.failure(
          error.message,
          request,
          sessionStorage,
          options,
          error,
        )
      }

      return await this.failure(
        'Unknown Error.',
        request,
        sessionStorage,
        options,
        new Error(JSON.stringify(error, null, 2)),
      )
    }

    if (!user) {
      throw new Error('Unable to authenticate.')
    }

    return this.success(user, request, sessionStorage, options)
  }

  private async validateEmailDefaults(email: string) {
    if (!/.+@.+/u.test(email)) {
      throw new Error(this.customErrors.invalidEmail)
    }
  }

  private async saveOtp(code: string) {
    await this.storeCode(code)
  }

  private async sendOtp(
    email: string,
    code: string,
    magicLink: string | undefined,
    form: FormData,
    request: Request,
  ) {
    const user = await this.verify({
      email,
      code,
      magicLink,
      form,
      request,
    }).catch(() => null)

    await this.sendCode({
      email,
      code,
      magicLink,
      user,
      form,
      request,
    })
  }

  private async validateOtpEncrypted(sessionOtpEncrypted: string) {
    // Retrieve encrypted OTP code from database.
    const dbPayload = await this.validateCode(sessionOtpEncrypted)

    if (
      !dbPayload ||
      typeof dbPayload.code !== 'string' ||
      typeof dbPayload.active !== 'boolean'
    ) {
      throw new Error('Code not found.')
    }

    const otpDecrypted = await decrypt(dbPayload.code, this.secret)
    const otp = JSON.parse(otpDecrypted)

    const sessionOtpDecrypted = await decrypt(sessionOtpEncrypted, this.secret)
    const sessionOtp = JSON.parse(sessionOtpDecrypted)

    const createdAt = new Date(otp.createdAt)
    const expiresAt = new Date(
      createdAt.getTime() +
        (this.codeGeneration.expiresAt ?? this.codeGenerationDefaults.expiresAt),
    )
    const maxAttempts =
      this.codeGeneration.maxAttempts ?? this.codeGenerationDefaults.maxAttempts

    if (dbPayload.active !== true) {
      throw new Error(this.customErrors.inactiveCode)
    }

    if (dbPayload.attempts >= maxAttempts) {
      throw new Error(this.customErrors.maxCodeAttemptsReached)
    }

    if (new Date() > expiresAt) {
      throw new Error(this.customErrors.expiredCode)
    }

    return { dbPayload, otp, sessionOtp }
  }

  private async validateOtp(code: string, sessionOtpEncrypted: string) {
    const { dbPayload, otp, sessionOtp } = await this.validateOtpEncrypted(
      sessionOtpEncrypted,
    )

    if (otp.code !== code) {
      // Update attempts count.
      await this.invalidateCode(
        sessionOtpEncrypted,
        dbPayload.active,
        dbPayload.attempts + 1,
      )
      throw new Error('Code does not match.')
    }

    if (otp.email !== sessionOtp.email) {
      throw new Error('Code does not match the provided email address.')
    }
  }

  private async validateMagicLink(magicLink: string, sessionOtpEncrypted: string) {
    if (magicLink !== sessionOtpEncrypted) {
      throw new Error('Magic Link does not match the expected Signature.')
    }

    const { otp, sessionOtp } = await this.validateOtpEncrypted(magicLink)

    if (otp.email !== sessionOtp.email) {
      throw new Error('Magic Link does not match the provided email address.')
    }
  }

  private async invalidateOtp(code: string, active?: boolean, attempts?: number) {
    await this.invalidateCode(code, active, attempts)
  }
}
