## Options and Customization

The Strategy includes a few options that can be customized.

## Email Validation

The email validation will match by default against a basic RegEx email pattern.
Feel free to customize it by passing `validateEmail` method to the TOTPStrategy Instance.

_This can be used to verify that the provided email is not a disposable one._

```ts
authenticator.use(
  new TOTPStrategy({
    validateEmail: async (email) => {
      // Handle custom email validation.
      // ...
    },
  }),
)
```

## TOTP Generation

The TOTP generation can customized by passing an object called `totpGeneration` to the TOTPStrategy Instance.

```ts
export interface TOTPGenerationOptions {
  /**
   * The secret used to generate the TOTP.
   * It should be Base32 encoded (Feel free to use: https://npm.im/thirty-two).
   *
   * Defaults to a random Base32 secret.
   * @default random
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

authenticator.use(
  new TOTPStrategy({
    totpGeneration: {
      digits: 6,
      period: 60,
      // ...
    },
  }),
)
```

## Custom Error Messages

The Strategy includes a few default error messages that can be customized by passing an object called `customErrors` to the TOTPStrategy Instance.

```ts
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
   * The rate limit exceeded error message.
   */
  rateLimitExceeded?: string

  /**
   * The expired TOTP error message.
   */
  expiredTotp?: string

  /**
   * The missing session email error message.
   */
  missingSessionEmail?: string

  /**
   * The missing session totp error message.
   */
  missingSessionTotp?: string
}

authenticator.use(
  new TOTPStrategy({
    customErrors: {
      requiredEmail: 'Whoops, email is required.',
    },
  }),
)
```

## Strategy Options

The Strategy includes a few more options that can be customized.

```ts
export interface TOTPStrategyOptions {
  /**
   * The secret used to encrypt the TOTP data.
   * Must be string of 64 hexadecimal characters.
   */
  secret: string

  /**
   * The optional cookie options.
   * @default undefined
   */
  cookieOptions?: Omit<SetCookieInit, 'name' | 'value'>

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
```

## Contributing

If you have any suggestion you'd like to share, feel free to open a PR!
