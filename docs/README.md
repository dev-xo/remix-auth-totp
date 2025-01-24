# Remix Auth TOTP Documentation

Welcome to the Remix Auth TOTP Documentation!

## List of Contents

- [Live Demo](https://totp.fly.dev) - A live demo that displays the authentication flow.
- [Getting Started](https://github.com/dev-xo/remix-auth-totp/tree/main/docs#getting-started) - A quick start guide to get you up and running.
- [Examples](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/examples.md) - A list of community examples using Remix Auth TOTP.
- [Customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) - A detailed guide of all the available options and customizations.
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

In the [Starter Example](https://github.com/dev-xo/totp-starter-example/blob/main/app/modules/email/email.server.ts) project, we can find a straightforward `sendEmail` implementation using [Resend](https://resend.com).

## Session Storage

We'll require to initialize a new Session Storage to work with. This Session will store user data and everything related to authentication.

Create a file called `session.server.ts` wherever you want.<br />
Implement the following code and replace the `secrets` property with a strong string into your `.env` file.

Same applies for Remix or React Router v7.

```ts
// app/modules/auth/session.server.ts
import { createCookieSessionStorage } from '@remix-run/node' // Or 'react-router'.

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
      emailSentRedirect: '/verify',
      magicLinkPath: '/verify',
      successRedirect: '/dashboard',
      failureRedirect: '/verify',
      sendTOTP: async ({ email, code, magicLink }) => {},
    },
    async ({ email }) => {},
  ),
)
```

> [!TIP]
> You can customize the cookie behavior by passing `cookieOptions` to the `sessionStorage` instance. Check [Customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) to learn more.

### 2: Implementing the Strategy Logic.

The Strategy Instance requires the following method: `sendTOTP`.

```ts
authenticator.use(
  new TOTPStrategy(
    {
      ...
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

The Strategy returns a `verify` method that allows handling our own logic. This includes creating the user, updating the session, etc.<br />

This should return the user data that will be stored in Session.

```ts
authenticator.use(
  new TOTPStrategy(
    {
      ...
      sendTOTP: async ({ email, code, magicLink }) => {}
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

      // Store user in session.
      const session = await getSession(request.headers.get("Cookie"));
      session.set("user", user);

      // Commit session.
      const sessionCookie = await commitSession(session);

      // Redirect to your authenticated route.
      throw redirect("/dashboard", {
        headers: {
          "Set-Cookie": sessionCookie,
        },
      });
    },
  ),
)
```

## Auth Routes

Last but not least, we'll require to create the routes that will handle the authentication flow. Create the following files inside the `app/routes` folder.

### `login.tsx`

```tsx
// app/routes/login.tsx
import { redirect } from 'react-router'
import { useFetcher } from 'react-router'
import { getSession } from '~/lib/session.server'
import { authenticator } from '~/lib/auth.server'

export async function loader({ request }: Route.LoaderArgs) {
  // Check for existing session.
  const session = await getSession(request.headers.get('Cookie'))
  const user = session.get('user')

  // If the user is already authenticated, redirect to dashboard.
  if (user) return redirect('/dashboard')

  return null
}

export async function action({ request }: Route.ActionArgs) {
  try {
    // Authenticate the user via TOTP (Form submission).
    return await authenticator.authenticate('TOTP', request)
  } catch (error) {
    console.log('error', error)

    // The error from TOTP includes the redirect Response with the cookie.
    if (error instanceof Response) {
      return error
    }

    // For other errors, return with error message.
    return {
      error: 'An error occurred during login. Please try again.',
    }
  }
}

export default function Login() {
  const fetcher = useFetcher()
  const isSubmitting = fetcher.state !== 'idle' || fetcher.formData != null
  const errors = fetcher.data?.error

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {/* Form. */}
      <fetcher.Form method="POST">
        <input
          type="email"
          name="email"
          placeholder="Insert email .."
          disabled={isSubmitting}
          required
        />
        <button type="submit">Send Code</button>
      </fetcher.Form>

      {/* Errors Handling. */}
      {errors && <p>{errors}</p>}
    </div>
  )
}
```

### `verify.tsx`

```tsx
// app/routes/verify.tsx
import { redirect, useLoaderData } from 'react-router'
import { Cookie } from '@mjackson/headers'
import { Link, useFetcher } from 'react-router'
import { useState } from 'react'
import { getSession } from '~/lib/session.server'
import { authenticator } from '~/lib/auth.server'

/**
 * Loader function that checks if the user is already authenticated.
 * - If the user is already authenticated, redirect to dashboard.
 * - If the user is not authenticated, check if the intent is to verify via magic-link URL.
 */
export async function loader({ request }: Route.LoaderArgs) {
  // Check for existing session.
  const session = await getSession(request.headers.get('Cookie'))
  const user = session.get('user')

  // If the user is already authenticated, redirect to dashboard.
  if (user) return redirect('/dashboard')

  // Get the TOTP cookie and the token from the URL.
  const cookie = new Cookie(request.headers.get('Cookie') || '')
  const totpCookie = cookie.get('_totp')

  const url = new URL(request.url)
  const token = url.searchParams.get('t')

  // Authenticate the user via magic-link URL.
  if (token) {
    try {
      return await authenticator.authenticate('TOTP', request)
    } catch (error) {
      if (error instanceof Response) return error
      if (error instanceof Error) return { error: error.message }
      return { error: 'Invalid TOTP' }
    }
  }

  // Get the email from the TOTP cookie.
  let email = null
  if (totpCookie) {
    const params = new URLSearchParams(totpCookie)
    email = params.get('email')
  }

  // If no email is found, redirect to login.
  if (!email) return redirect('/auth/login')

  return { email }
}

/**
 * Action function that handles the TOTP verification form submission.
 * - Authenticates the user via TOTP (Form submission).
 */
export async function action({ request }: Route.ActionArgs) {
  try {
    // Authenticate the user via TOTP (Form submission).
    return await authenticator.authenticate('TOTP', request)
  } catch (error) {
    if (error instanceof Response) {
      const cookie = new Cookie(error.headers.get('Set-Cookie') || '')
      const totpCookie = cookie.get('_totp')
      if (totpCookie) {
        const params = new URLSearchParams(totpCookie)
        return { error: params.get('error') }
      }

      throw error
    }
    return { error: 'Invalid TOTP' }
  }
}

export default function Verify() {
  const loaderData = useLoaderData<typeof loader>()

  const [value, setValue] = useState('')
  const fetcher = useFetcher()
  const isSubmitting = fetcher.state !== 'idle' || fetcher.formData != null

  const code = 'code' in loaderData ? loaderData.code : undefined
  const email = 'email' in loaderData ? loaderData.email : undefined
  const error = 'error' in loaderData ? loaderData.error : null
  const errors = fetcher.data?.error || error

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {/* Code Verification Form */}
      <fetcher.Form method="POST">
        <input
          required
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={isSubmitting}
          placeholder="Enter the 6-digit code"
        />
        <button type="submit">Continue</button>
      </fetcher.Form>

      {/* Renders the form that requests a new code. */}
      {/* Email input is not required, it's already stored in Session. */}
      <fetcher.Form method="POST" action="/auth/login">
        <button type="submit">Request new Code</button>
      </fetcher.Form>

      {/* Errors Handling. */}
      {errors && <p>{errors}</p>}
    </div>
  )
}
```

### `dashboard.tsx`

```tsx
// app/routes/dashboard.tsx
import { Link } from 'react-router'
import { getSession } from '../lib/session.server'
import { redirect } from 'react-router'
import { useLoaderData } from 'react-router'

export async function loader({ request }: Route.LoaderArgs) {
  const session = await getSession(request.headers.get('Cookie'))
  const user = session.get('user')

  if (!user) return redirect('/auth/login')
  console.log('Dashboard user', user)

  return { user }
}

export default function Account() {
  let { user } = useLoaderData<typeof loader>()

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <h1>{user && `Welcome ${user.email}`}</h1>

      {/* Log out */}
      <Link to="/auth/logout">Log out</Link>
    </div>
  )
}
```

### `logout.tsx`

```tsx
// app/routes/logout.tsx
import { sessionStorage } from '~/lib/session.server'
import { redirect } from 'react-router'

export async function loader({ request }: Route.LoaderArgs) {
  // Get the session.
  const session = await sessionStorage.getSession(request.headers.get('Cookie'))

  // Destroy the session and redirect to login.
  return redirect('/auth/login', {
    headers: {
      'Set-Cookie': await sessionStorage.destroySession(session),
    },
  })
}
```

Done! 🎉 Feel free to check the [Starter Example for React Router v7](https://github.com/dev-xo/remix-auth-totp-v4-starter) for a detailed implementation.

## [Options and Customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md)

The Strategy includes a few options that can be customized.

You can find a detailed list of all the available options in the [customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) documentation.
