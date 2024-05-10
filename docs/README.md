# Remix Auth TOTP Documentation

Welcome to the Remix Auth TOTP Documentation!

## List of Contents

- [Live Demo](https://totp.fly.dev) - A live demo that displays the authentication flow.
- [Getting Started](https://github.com/dev-xo/remix-auth-totp/tree/main/docs#getting-started) - A quick start guide to get you up and running.
- [Examples](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/examples.md) - A list of community examples using Remix Auth TOTP.
- [Customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) - A detailed guide of all the available options and customizations.
- [Migration](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/migration.md) - A `v2` to `v3` migration guide.
- [Cloudflare](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/cloudflare.md) - A guide to using Remix Auth TOTP with Cloudflare Workers.

## Getting Started

Remix Auth TOTP exports one required method:

- `sendTOTP` - Sends the TOTP code to the user via email or any other method.

Here's a basic overview of the authentication flow.

1. Users Sign Up or Log In via email.
2. The Strategy generates and securely sends a Time-based One-Time Password (TOTP) to the user.
3. Users submit the Code through a Form or Magic Link.
4. The Strategy validates the TOTP Code, ensuring a secure authentication process.
   <br />

> [!NOTE]
> Remix Auth TOTP is only Remix v2.0+ compatible.

Let's see how we can implement the Strategy into our Remix App.

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

Create a file called `auth.server.ts` wherever you want. <br />

> [!IMPORTANT]
> A random 64-character hexadecimal string is required to generate the TOTP codes. This string should be stored securely and not shared with anyone.
> You can use a site like https://www.grc.com/passwords.htm to generate a strong secret.

Implement the following code and replace the `secret` property with a string containing exactly 64 random hexadecimal characters (0-9 and A-F) into your `.env` file. An example is `928F416BAFC49B969E62052F00450B6E974B03E86DC6984D1FA787B7EA533227`.

```ts
// app/modules/auth/auth.server.ts
import { Authenticator } from 'remix-auth'
import { TOTPStrategy } from 'remix-auth-totp'
import { sessionStorage } from './session.server'
import { sendEmail } from './email.server'
import { db } from '~/db'

type User = {
  id: string
  email: string
}

export let authenticator = new Authenticator<User>(sessionStorage)

authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET || 'NOT_A_STRONG_SECRET',
      sendTOTP: async ({ email, code, magicLink }) => {},
    },
    async ({ email }) => {},
  ),
)
```

> [!TIP]
> You can specify session duration with `maxAge` in seconds. Default is `undefined`, persisting across browser restarts.

### 2: Implementing the Strategy Logic.

The Strategy Instance requires the following method: `sendTOTP`.

```ts
authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET,

      sendTOTP: async ({ email, code, magicLink }) => {
        // Send the TOTP code to the user.
        await sendEmail({ email, code, magicLink })
      },
    },
    async ({ email }) => {},
  ),
)
```

### 3. Creating and Storing the User.

The Strategy returns a `verify` method that allows handling our own logic. This includes creating the user, updating the user, etc.<br />

This should return the user data that will be stored in Session.

```ts
authenticator.use(
  new TOTPStrategy(
    {
      // createTOTP: async (data) => {},
      // ...
    },
    async ({ email }) => {
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
import type { LoaderFunctionArgs, ActionFunctionArgs } from '@remix-run/node'
import { json } from '@remix-run/node'
import { Form, useLoaderData } from '@remix-run/react'
import { authenticator } from '~/modules/auth/auth.server'
import { getSession, commitSession } from '~/modules/auth/session.server'

export async function loader({ request }: LoaderFunctionArgs) {
  await authenticator.isAuthenticated(request, {
    successRedirect: '/account',
  })
  const session = await getSession(request.headers.get('Cookie'))
  const authError = session.get(authenticator.sessionErrorKey)

  // Commit session to clear any `flash` error message.
  return json(
    { authError },
    {
      headers: {
        'set-cookie': await commitSession(session),
      },
    },
  )
}

export async function action({ request }: ActionFunctionArgs) {
  await authenticator.authenticate('TOTP', request, {
    // The `successRedirect` route will be used to verify the OTP code.
    // This could be the current pathname or any other route that renders the verification form.
    successRedirect: '/verify',

    // The `failureRedirect` route will be used to render any possible error.
    // If not provided, ErrorBoundary will be rendered instead.
    failureRedirect: '/login',
  })
}

export default function Login() {
  let { authError } = useLoaderData<typeof loader>()

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {/* Login Form. */}
      <Form method="POST">
        <label htmlFor="email">Email</label>
        <input type="email" name="email" placeholder="Insert email .." required />
        <button type="submit">Send Code</button>
      </Form>

      {/* Login Errors Handling. */}
      <span>{authError?.message}</span>
    </div>
  )
}
```

### `verify.tsx`

```tsx
// app/routes/verify.tsx
import type { LoaderFunctionArgs, ActionFunctionArgs } from '@remix-run/node'
import { json, redirect } from '@remix-run/node'
import { Form, useLoaderData } from '@remix-run/react'
import { authenticator } from '~/modules/auth/auth.server.ts'
import { getSession, commitSession } from '~/modules/auth/auth-session.server.ts'

export async function loader({ request }: LoaderFunctionArgs) {
  await authenticator.isAuthenticated(request, {
    successRedirect: '/account',
  })

  const session = await getSession(request.headers.get('cookie'))
  const authEmail = session.get('auth:email')
  const authError = session.get(authenticator.sessionErrorKey)
  if (!authEmail) return redirect('/login')

  // Commit session to clear any `flash` error message.
  return json({ authError }, {
    headers: {
      'set-cookie': await commitSession(session),
    },
  })
}

export async function action({ request }: ActionFunctionArgs) {
  const url = new URL(request.url)
  const currentPath = url.pathname

  await authenticator.authenticate('TOTP', request, {
    successRedirect: currentPath,
    failureRedirect: currentPath,
  })
}

export default function Verify() {
  const { authError } = useLoaderData<typeof loader>()

  return (
    <div style={{ display: 'flex' flexDirection: 'column' }}>
      {/* Code Verification Form */}
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

      {/* Errors Handling. */}
      <span>{authError?.message}</span>
    </div>
  )
}
```

### `account.tsx`

```tsx
// app/routes/account.tsx
import type { LoaderFunctionArgs } from '@remix-run/node'
import { json } from '@remix-run/node'
import { Form, useLoaderData } from '@remix-run/react'
import { authenticator } from '~/modules/auth/auth.server'

export async function loader({ request }: LoaderFunctionArgs) {
  const user = await authenticator.isAuthenticated(request, {
    failureRedirect: '/',
  })
  return json({ user })
}

export default function Account() {
  let { user } = useLoaderData<typeof loader>()

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
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
import type { LoaderFunctionArgs } from '@remix-run/node'
import { authenticator } from '~/modules/auth/auth.server'

export async function loader({ request }: LoaderFunctionArgs) {
  await authenticator.authenticate('TOTP', request, {
    successRedirect: '/account',
    failureRedirect: '/login',
  })
}
```

### `logout.tsx`

```tsx
// app/routes/logout.tsx
import type { ActionFunctionArgs } from '@remix-run/node'
import { authenticator } from '~/modules/auth/auth.server'

export async function action({ request }: ActionFunctionArgs) {
  return await authenticator.logout(request, {
    redirectTo: '/',
  })
}
```

Done! 🎉 Feel free to check the [Starter Example](https://github.com/dev-xo/totp-starter-example) for a detailed implementation.

## [Options and Customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md)

The Strategy includes a few options that can be customized.

You can find a detailed list of all the available options in the [customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) documentation.
