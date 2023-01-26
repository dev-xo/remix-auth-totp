import { SessionStorage, redirect } from '@remix-run/server-runtime'
import { AuthenticateOptions, Strategy, StrategyVerifyCallback } from 'remix-auth'
import { encrypt, decrypt, generateOtp } from './utils'

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
   * The user object.
   */
  user?: User | null

  /**
   * The formData object.
   */
  form?: FormData
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
 * @param attempts The number of attempts.
 */
export interface InvalidateCodeFunction {
  (code: string, active?: boolean, attempts?: number): Promise<void>
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
   * The code generation configuration.
   */
  codeGeneration?: CodeGenerationOptions

  /**
   * The validate email function.
   */
  validateEmail?: ValidateEmailFunction

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
   * A FormData object that contains the form
   * used to trigger the authentication.
   */
  form?: FormData
}

export class OTPStrategy<User> extends Strategy<User, OTPVerifyParams> {
  public name = 'OTP'

  private readonly secret: string
  private readonly emailField: string
  private readonly codeField: string
  private readonly codeGeneration: CodeGenerationOptions
  private readonly validateEmail: ValidateEmailFunction
  private readonly storeCode: StoreCodeFunction
  private readonly sendCode: SendCodeFunction<User>
  private readonly validateCode: ValidateCodeFunction
  private readonly invalidateCode: InvalidateCodeFunction
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

  constructor(
    options: OTPStrategyOptions<User>,
    verify: StrategyVerifyCallback<User, OTPVerifyParams>,
  ) {
    super(verify)
    this.secret = options.secret ?? ''
    this.emailField = options.emailField ?? 'email'
    this.codeField = options.codeField ?? 'code'
    this.codeGeneration = options.codeGeneration ?? this.codeGenerationDefaults
    this.validateEmail = options.validateEmail ?? this.validateEmailDefaults
    this.storeCode = options.storeCode
    this.sendCode = options.sendCode
    this.validateCode = options.validateCode
    this.invalidateCode = options.invalidateCode
    this.sessionEmailKey = options.sessionEmailKey ?? 'auth:email'
    this.sessionOtpKey = options.sessionOtpKey ?? 'auth:otp'
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions,
  ): Promise<User> {
    if (!this.secret) {
      throw new Error('Missing required secret option.')
    }

    // Initializes Session.
    const session = await sessionStorage.getSession(request.headers.get('Cookie'))

    // Initializes user variable.
    let user: User | null = session.get(options.sessionKey) ?? null

    try {
      if (!user && request.method === 'POST') {
        if (!options.successRedirect) {
          throw new Error('Missing required successRedirect option.')
        }

        const formData = await request.formData()
        const form = Object.fromEntries(formData)

        // Email will be re-assigned if user requests a new OTP code.
        let email = form[this.emailField] && String(form[this.emailField])
        const code = form[this.codeField] && String(form[this.codeField])

        const sessionEmail = session.get(this.sessionEmailKey)
        const sessionOtpEncrypted = session.get(this.sessionOtpKey)

        // Requests a new OTP code.
        if (!code && sessionEmail && sessionOtpEncrypted) {
          // Invalidates previous OTP code.
          await this.invalidateOtp(sessionOtpEncrypted, false)

          // Reassigns email. (Required for OTP code generation.)
          email = sessionEmail
        }

        // First Authentication part.
        // OTP code is encrypted, stored in database and sent to the user via email.
        if (!code) {
          if (!email) {
            throw new Error('Missing required email field.')
          }
          await this.validateEmail(email)

          // Encrypts OTP code.
          const otp = generateOtp({ ...this.codeGeneration })
          const otpEncrypted = await encrypt(
            JSON.stringify({ email, ...otp }),
            this.secret,
          )

          // Stores and sends OTP code.
          await this.saveOtp(otpEncrypted)
          await this.sendOtp(email, otp.code, formData)

          session.set(this.sessionEmailKey, email)
          session.set(this.sessionOtpKey, otpEncrypted)
          session.unset(options.sessionErrorKey)

          throw redirect(options.successRedirect, {
            headers: {
              'Set-Cookie': await sessionStorage.commitSession(session),
            },
          })
        }

        // Second Authentication part.
        // OTP code is decrypted, validated and user will be authenticated.
        if (code) {
          if (!session.has(this.sessionEmailKey)) {
            throw new Error('Missing required email from Session.')
          }
          if (!session.has(this.sessionOtpKey)) {
            throw new Error('Missing required code from Session.')
          }

          // Handles code validation.
          await this.validateOtp(code, sessionOtpEncrypted)
          await this.invalidateOtp(sessionOtpEncrypted, false)

          // Gets and sets user data.
          user = await this.verify({ email: sessionEmail, form: formData })

          session.set(options.sessionKey, user)
          session.unset(this.sessionEmailKey)
          session.unset(this.sessionOtpKey)
          session.unset(options.sessionErrorKey)

          throw redirect(options.successRedirect, {
            headers: { 'Set-Cookie': await sessionStorage.commitSession(session) },
          })
        }
      }
    } catch (error) {
      if (error instanceof Response && error.status === 302) {
        throw error
      }

      if (error instanceof Error) {
        if (error.message === 'Code has reached maximum attempts.') {
          // Invalidates maximum attempted OTP code.
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
      throw new Error('Invalid email address.')
    }
  }

  private async saveOtp(code: string) {
    await this.storeCode(code)
  }

  private async sendOtp(email: string, code: string, form: FormData) {
    const user = await this.verify({
      email,
      code,
      form,
    }).catch(() => null)

    await this.sendCode({
      email,
      code,
      user,
      form,
    })
  }

  private async validateOtp(code: string, sessionOtpEncrypted: string) {
    // Retrieves encrypted OTP code from database.
    const dbPayload = await this.validateCode(sessionOtpEncrypted)

    if (
      !dbPayload ||
      typeof dbPayload.code !== 'string' ||
      typeof dbPayload.active !== 'boolean'
    ) {
      throw new Error('OTP code not found.')
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
      throw new Error('Code is not active.')
    }

    if (dbPayload.attempts >= maxAttempts) {
      throw new Error('Code has reached maximum attempts.')
    }

    if (new Date() > expiresAt) {
      throw new Error('Code has expired.')
    }

    if (otp.code !== code) {
      // Updates the attempts count.
      await this.invalidateCode(
        sessionOtpEncrypted,
        dbPayload.active,
        dbPayload.attempts + 1,
      )
      throw new Error('Code is not valid.')
    }

    if (otp.email !== sessionOtp.email) {
      throw new Error('Code does not match provided email address.')
    }
  }

  private async invalidateOtp(code: string, active?: boolean, attempts?: number) {
    await this.invalidateCode(code, active, attempts)
  }
}
