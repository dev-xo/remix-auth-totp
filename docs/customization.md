## Options and Customization

The Strategy includes a few options that can be customized.

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

## Cloudflare

### Remix v2 Compiler

To use it on the Cloudflare runtime, you'll need to add the following to your `remix.config.js` file to specify the polyfills for a couple of Node built-in modules. See the Remix Docs on [supportNodeBuiltinsPolyfill](https://remix.run/docs/en/main/file-conventions/remix-config#servernodebuiltinspolyfill).

### `remix.config.js`

```js
export default {
  serverNodeBuiltinsPolyfill: {
    modules: { buffer: true, crypto: true },
    globals: {
      Buffer: true,
    },
  },
}
```

### Vite

Enable [Nodejs compatiblity](https://developers.cloudflare.com/workers/runtime-apis/nodejs/) for Cloudflare in [wrangler.toml](https://developers.cloudflare.com/workers/runtime-apis/nodejs/#enable-nodejs-with-workers), [Cloudflare Dashboard](https://developers.cloudflare.com/workers/runtime-apis/nodejs/#enable-nodejs-from-the-cloudflare-dashboard), and in the start script inside `package.json`.

```json
"scripts": {
  "start": "wrangler pages dev ./build/client --compatibility-flags=nodejs_compat"
}
```

Ensure the `Buffer` global is set up before using `remix-auth-totp`.

```ts
import { Buffer } from 'node:buffer'

function setUpGlobals() {
  globalThis.Buffer = Buffer
}
```

### Using Cloudflare KV for Session Storage

```ts
const sessionStorage = createWorkersKVSessionStorage({
  kv: KV,
  cookie: {
    name: '_auth',
    path: '/',
    sameSite: 'lax',
    httpOnly: true,
    secrets: [SESSION_SECRET],
    secure: ENVIRONMENT === 'production',
  },
})

const authenticator = new Authenticator<SessionUser>(sessionStorage)

authenticator.use(
  new TOTPStrategy(
    {
      secret: TOTP_SECRET,
      sendTOTP: async ({ email, code, magicLink }) => {},
    },
    async ({ email }) => {},
  ),
)
```

## Contributing

If you have any suggestion you'd like to share, feel free to open a PR!
