<!-- <div align="center">
  <a href="https://github.com/dev-xo/remix-auth-totp" target="_blank">
    <img alt="Remix Auth TOTP" src="https://raw.githubusercontent.com/dev-xo/dev-xo/main/remix-auth-totp/logo-4.png" width="200" />
  </a>
</div> -->

<h1 align="center">
  💿 Remix Auth TOTP
</h1>

<div align="center">
  <p>
    Remix Auth TOTP is a <strong>Time-Based One-Time Password (TOTP) Authentication Strategy</strong> for <a href="https://github.com/sergiodxa/remix-auth">Remix Auth</a> that supports <strong>Email Verification & Two Factor Authentication (2FA)</strong> in your application.
  </p>
</div>

<div align="center">
  <p>
    <!-- <br /> -->
    <a href="https://github.com/dev-xo/remix-auth-totp?tab=readme-ov-file#features"><strong>Explore Docs »</strong></a>
    <br/><br/>
    <a href="https://totp.fly.dev">Live Demo</a>
    ·
    <a href="https://github.com/dev-xo/remix-auth-totp/blob/main/docs/examples.md">Examples</a>
  </p>
</div>

```
npm install remix-auth-totp
```

[![CI](https://img.shields.io/github/actions/workflow/status/dev-xo/remix-auth-totp/main.yml?label=Build)](https://github.com/dev-xo/remix-auth-totp/actions/workflows/main.yml)
[![Release](https://img.shields.io/npm/v/remix-auth-totp.svg?&label=Release)](https://www.npmjs.com/package/remix-auth-totp)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/dev-xo/remix-auth-totp/blob/main/LICENSE)

## Features

- **😌 Easy to Set Up** - Manages the entire authentication flow for you.
- **🔐 Secure** - Features encrypted time-based codes.
- **📧 Built-In Magic Link** - Authenticate users with a click.
- **📚 Single Source of Truth** - A database of your choice.
- **🛡 Bulletproof** - Crafted in strict TypeScript with high test coverage.
- **🚀 Remix Auth Foundation** - An amazing authentication library for Remix.

## [Live Demo](https://totp.fly.dev)

[Live Demo](https://totp.fly.dev) that displays the authentication flow.

[![Remix Auth TOTP](https://raw.githubusercontent.com/dev-xo/dev-xo/main/remix-auth-totp/thumbnail-2.png)](https://totp.fly.dev)

## Usage

Remix Auth TOTP exports three required methods:

- `storeTOTP` - Stores the generated OTP into database.
- `sendTOTP` - Sends the OTP to the user via email or any other method.
- `handleTOTP` - Handles / Updates the already stored OTP from database.

Here's a basic overview of the authentication process.

1. The user signs-up / logs-in via email address.
2. The Strategy generates a new OTP, stores it and sends it to the user.
3. The user submits the code via form submission / magic-link click.
4. The Strategy validates the OTP code and authenticates the user.
   <br />

> [!NOTE]
> Remix Auth TOTP is only Remix v2.0+ compatible.

Let's see how we can implement the Strategy into our Remix App.

## Database

We'll require a database to store our encrypted OTP codes.

For this example we'll use Prisma ORM with a SQLite database. As long as your database supports the following fields, you can use any database of choice.

```ts
/**
 * Required Fields:
 * - `hash`: String
 * - `active`: Boolean, default: true
 * - `attempts`: Int (Number), default: 0
 *
 * Optional Fields:
 * - `expiresAt`: DateTime (Date), @default(now()) | String, @default("")
 */
model Totp {
  id String @id @default(uuid())

  /// The encrypted data used to generate the OTP.
  hash String @unique

  /// The status of the OTP.
  /// Used internally / programmatically to invalidate OTPs.
  active Boolean @default(true)

  /// The input attempts of the OTP.
  /// Used internally to invalidate OTPs after a certain amount of attempts.
  attempts Int @default(0)

  /// The expiration date of the OTP.
  /// Used programmatically to invalidate unused OTPs.
  expiresAt DateTime? @default(now())
}
```

## Email Service

We'll require an Email Service to send the codes to our users. Feel free to use any service of choice, such as [Resend](https://resend.com), [Mailgun](https://www.mailgun.com), [Sendgrid](https://sendgrid.com), etc. The goal is to have a sender function similar to the following one.

```ts
export type SendEmailBody = {
  to: string | string[]
  subject: string
  html: string
  text?: string
}

export async function sendEmail(body: SendEmailBody) {
  return fetch(`https://any-email-service.com`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.EMAIL_PROVIDER_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ ...body }),
  })
}
```

In the [Starter Example](https://github.com/dev-xo/totp-starter-example) project, we can find a straightforward `sendEmail` implementation using [Resend](https://resend.com).

## Session Storage

We'll require to initialize a new Cookie Session Storage to work with. This Session will store user data and everything related to authentication.

Create a file called `session.server.ts` wherever you want.<br />
Implement the following code and replace the `secrets` property with a strong string into your `.env` file.

```ts
// app/modules/auth/session.server.ts
import { createCookieSessionStorage } from '@remix-run/node'

export const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: '_auth',
    sameSite: 'lax',
    path: '/',
    httpOnly: true,
    secrets: [process.env.SESSION_SECRET || 'NOT_A_STRONG_SECRET'],
    secure: process.env.NODE_ENV === 'production',
  },
})

export const { getSession, commitSession, destroySession } = sessionStorage
```

## Strategy Instance

Now that we have everything set up, we can start implementing the Strategy Instance.

### 1. Implementing the Strategy Instance.

Create a file called `auth.server.ts` wherever you want.<br />
Implement the following code and replace the `secret` property with a strong string into your `.env` file.

```ts
// app/modules/auth/auth.server.ts
import { Authenticator } from 'remix-auth'
import { TOTPStrategy } from 'remix-auth-totp'

import { sessionStorage } from './session.server'
import { sendEmail } from './email.server'
import { db } from '~/db'

// The User type should match the one from database.
type User = {
  id: string
  email: string
}

export let authenticator = new Authenticator<User>(sessionStorage, {
  throwOnError: true,
})

authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET || 'NOT_A_STRONG_SECRET',
      storeTOTP: async (data) => {},
      sendTOTP: async ({ email, code, magicLink, user, form, request }) => {},
      handleTOTP: async (hash, data) => {},
    },
    async ({ email, code, form, magicLink, request }) => {},
  ),
)
```

> [!TIP]
> You can specify session duration with `maxAge` in milliseconds. Default is `undefined`, persisting across browser restarts.

### 2: Implementing the Strategy Logic.

The Strategy Instance requires the following three methods: `storeTOTP`, `sendTOTP`, `handleTOTP`.

```ts
authenticator.use(
  new TOTPStrategy({
    secret: process.env.ENCRYPTION_SECRET,

    storeTOTP: async (data) => {
      // Store the generated OTP into database.
      await db.totp.create({ data })
    },
    sendTOTP: async ({ email, code, magicLink }) => {
      // Send the generated OTP to the user.
      await sendEmail({ email, code, magicLink })
    },
    handleTOTP: async (hash, data) => {
      const totp = await db.totp.findUnique({ where: { hash } })

      // If `data` is provided, the Strategy will update the totp.
      // Used for internal checks / invalidations.
      if (data) {
        return await db.totp.update({
          where: { hash },
          data: { ...data },
        })
      }

      // Otherwise, we'll return it.
      // Used for internal checks / validations.
      return totp
    },

    async ({ email, code, magicLink, form, request }) => {},
  }),
)
```

All of this CRUD methods should be replaced and adapted with the ones provided by our database.

### 3. Creating and Storing the User.

The Strategy returns a `verify` method that allows handling our own logic. This includes creating the user, updating the user, etc.<br />

This should return the user data that will be stored in Session.

```ts
authenticator.use(
  new OTPStrategy(
    {
      // We've already set up these options.
      // storeTOTP: async (data) => {},
      // ...
    },
    async ({ email, code, magicLink, form, request }) => {
      // You can determine whether the user is authenticating
      // via OTP code submission or Magic-Link URL and run your own logic.
      if (form) console.log('Optional form submission logic.')
      if (magicLink) console.log('Optional magic-link submission logic.')

      // Get user from database.
      let user = await db.user.findFirst({
        where: { email },
      })

      // Create a new user if it doesn't exist.
      if (!user) {
        user = await db.user.create({
          data: { email },
        })
      }

      // Return user as Session.
      return user
    },
  ),
)
```

## Auth Routes

Last but not least, we'll require to create the routes that will handle the authentication flow. Create the following files inside the `app/routes` folder.

### `login.tsx`

```tsx
// app/routes/login.tsx
import type { DataFunctionArgs } from '@remix-run/node'
import { json } from '@remix-run/node'
import { Form, useLoaderData } from '@remix-run/react'

import { authenticator } from '~/modules/auth/auth.server'
import { getSession, commitSession } from '~/modules/auth/session.server'

export async function loader({ request }: DataFunctionArgs) {
  await authenticator.isAuthenticated(request, {
    successRedirect: '/account',
  })

  const cookie = await getSession(request.headers.get('Cookie'))
  const authEmail = cookie.get('auth:email')
  const authError = cookie.get(authenticator.sessionErrorKey)

  // Commit session to clear any `flash` error message.
  return json(
    { authEmail, authError },
    {
      headers: {
        'set-cookie': await commitSession(session),
      },
    },
  )
}

export async function action({ request }: DataFunctionArgs) {
  await authenticator.authenticate('TOTP', request, {
    // The `successRedirect` route it's required.
    // ...
    // User is not authenticated yet.
    // We want to redirect to our verify code form. (/verify-code or any other route).
    successRedirect: '/login',

    // The `failureRedirect` route it's required.
    // ...
    // We want to display any possible error message.
    // If not provided, ErrorBoundary will be rendered instead.
    failureRedirect: '/login',
  })
}

export default function Login() {
  let { authEmail, authError } = useLoaderData<typeof loader>()

  return (
    <div style={{ display: 'flex' flexDirection: 'column' }}>
      {/* Email Form. */}
      {!authEmail && (
        <Form method="POST">
          <label htmlFor="email">Email</label>
          <input type="email" name="email" placeholder="Insert email .." required />
          <button type="submit">Send Code</button>
        </Form>
      )}

      {/* Code Verification Form. */}
      {authEmail && (
        <div style={{ display: 'flex' flexDirection: 'column' }}>
          {/* Renders the form that verifies the code. */}
          <Form method="POST">
            <label htmlFor="code">Code</label>
            <input type="text" name="code" placeholder="Insert code .." required />

            <button type="submit">Continue</button>
          </Form>

          {/* Renders the form that requests a new code. */}
          {/* Email input is not required, it's already stored in Session. */}
          <Form method="POST">
            <button type="submit">Request new Code</button>
          </Form>
        </div>
      )}

      {/* Email Errors Handling. */}
      {!authEmail && (<span>{authError?.message || email?.error}</span>)}
      {/* Code Errors Handling. */}
      {authEmail && (<span>{authError?.message || code?.error}</span>)}
    </div>
  )
}
```

### `account.tsx`

```tsx
// app/routes/account.tsx
import type { DataFunctionArgs } from '@remix-run/node'

import { json } from '@remix-run/node'
import { Form, useLoaderData } from '@remix-run/react'
import { authenticator } from '~/modules/auth/auth.server'

export async function loader({ request }: DataFunctionArgs) {
  const user = await authenticator.isAuthenticated(request, {
    failureRedirect: '/',
  })
  return json({ user })
}

export default function Account() {
  let { user } = useLoaderData<typeof loader>()

  return (
    <div style={{ display: 'flex' flexDirection: 'column' }}>
      <h1>{user && `Welcome ${user.email}`}</h1>
      <Form action="/logout" method="POST">
        <button>Log out</button>
      </Form>
    </div>
  )
}
```

### `magic-link.tsx`

```tsx
// app/routes/magic-link.tsx
import type { DataFunctionArgs } from '@remix-run/node'
import { authenticator } from '~/modules/auth/auth.server'

export async function loader({ request }: DataFunctionArgs) {
  await authenticator.authenticate('TOTP', request, {
    successRedirect: '/account',
    failureRedirect: '/login',
  })
}
```

### `logout.tsx`

```tsx
// app/routes/logout.tsx
import type { DataFunctionArgs } from '@remix-run/node'
import { authenticator } from '~/modules/auth/auth.server'

export async function action({ request }: DataFunctionArgs) {
  return await authenticator.logout(request, {
    redirectTo: '/',
  })
}
```

Done! 🎉 Feel free to check the [Starter Example](https://github.com/dev-xo/totp-starter-example) for a detailed implementation.

## [Options and Customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md)

The Strategy includes a few options that can be customized.

You can find a detailed list of all the available options in the [customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) documentation.

## Support

If you found this library helpful, please consider leaving us a ⭐ [star](https://github.com/dev-xo/remix-auth-totp). It helps the repository grow and provides the necessary motivation to continue maintaining the project.

### Acknowledgments

Bit thanks to [@w00fz](https://github.com/w00fz) for its amazing implementation of the **Magic Link feature** and to [@mw10013](https://github.com/mw10013) for the **Cloudflare support** and the dedication set into the implementation.

## License

Licensed under the [MIT license](https://github.com/dev-xo/remix-auth-totp/blob/main/LICENSE).
