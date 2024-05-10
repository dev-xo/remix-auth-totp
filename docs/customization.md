## Options and Customization

The Strategy includes a few options that can be customized.

## Passing a pre-read FormData Object

Because you may want to do validations or read values from the FormData before calling `authenticate`, `remix-auth-totp` allows you to pass a FormData object as part of the optional context.

```ts
export async function action({ request }: ActionFunctionArgs) {
  const formData = await request.formData()
  await authenticator.authenticate(type, request, {
    successRedirect: formData.get('redirectTo'),
    failureRedirect: '/login',
    context: { formData }, // Pass pre-read formData.
  })
}
```

This way, you don't need to clone the request yourself.

See https://github.com/sergiodxa/remix-auth-form?tab=readme-ov-file#passing-a-pre-read-formdata-object

### Email Validation

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

### TOTP Generation

The TOTP generation can customized by passing an object called `totpGeneration` to the TOTPStrategy Instance.

```ts
export interface TOTPGenerationOptions {
  /**
   * The secret used to generate the OTP.
   * It should be Base32 encoded (Feel free to use: https://npm.im/thirty-two).
   * @default Random Base32 secret.
   */
  secret?: string
  /**
   * The algorithm used to generate the OTP.
   * @default 'SHA1'
   */
  algorithm?: string
  /**
   * The character set used to generate the OTP.
   * @default 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
   */
  charSet?: string
  /**
   * The number of digits the OTP will have.
   * @default 6
   */
  digits?: number
  /**
   * The number of seconds the OTP will be valid.
   * @default 60
   */
  period?: number
  /**
   * The number of attempts the user has to verify the OTP.
   * @default 3
   */
  maxAttempts: number
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

### Custom Error Messages

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
   * The expired TOTP error message.
   */
  expiredTotp?: string
}

authenticator.use(
  new TOTPStrategy({
    customErrors: {
      requiredEmail: 'Whoops, email is required.',
    },
  }),
)
```

### More Options

The Strategy includes a few more options that can be customized.

```ts
export interface TOTPStrategyOptions<User> {
  /**
   * The secret used to encrypt the session.
   */
  secret: string
  /**
   * The maximum age of the session in seconds.
   * @default undefined
   */
  maxAge?: number
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
   * The session key that stores the TOTP data.
   * @default "auth:totp"
   */
  sessionTotpKey?: string
  /**
   * The URL path for the Magic Link.
   * @default '/magic-link'
   */
  magicLinkPath?: string
}
```

## Contributing

If you have any suggestion you'd like to share, feel free to open a PR!
