# Remix Auth TOTP Documentation

Welcome to the Remix Auth TOTP Documentation!

## List of Contents

- 🚀 [Live Demo](https://totp.devxo.workers.dev) - See it in action.
- 🏁 [Getting Started](https://github.com/dev-xo/remix-auth-totp/tree/main/docs#getting-started) - Quick setup guide.
- 🎯 [Examples](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/examples.md) - Community examples.
- ⚙️ [Customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) - Configuration options.
- ☁️ [Cloudflare](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/cloudflare.md) - Cloudflare Workers setup.

## Getting Started

Remix Auth TOTP exports one required method:

- `sendTOTP` - Sends the TOTP code to the user via email or any other method.

The authentication flow is simple:

1. User enters their email.
2. User receives a one-time code via email.
3. User submits the code or clicks magic link.
4. Code is validated and user is authenticated.
   <br />

> [!NOTE]
> Remix Auth TOTP is compatible with Remix v2.0+ and React Router v7.

Let's see how we can implement the Strategy into our app.

## Email Service

We'll require an Email Service to send the codes to our users.

Feel free to use any service of choice, such as [Resend](https://resend.com), [Mailgun](https://www.mailgun.com), [Sendgrid](https://sendgrid.com), etc. The goal is to have a sender function similar to the following one.

```ts
export type SendEmailBody = {
  sender: {
    name: string
    email: string
  }
  to: {
    name?: string
    email: string
  }[]
  subject: string
  htmlContent: string
}

export async function sendEmail(body: SendEmailBody) {
  const sender = {
    name: 'Your Name',
    email: 'your-email@example.com',
  }

  return fetch(`https://any-email-service.com`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'content-type': 'application/json',
      'api-key': process.env.EMAIL_API_KEY as string,
    },
    body: JSON.stringify({ ...body }),
  })
}
```

For a working example, see the [Remix Saas - Email](https://github.com/dev-xo/remix-saas/blob/main/app/modules/email/email.server.ts) implementation using Resend API.

## Session Storage

We'll require to initialize a new Session Storage to work with. This Session will store user data and everything related to the TOTP authentication.

```ts
// app/lib/auth-session.server.ts
import { createCookieSessionStorage } from 'react-router' // Or '@remix-run'.

export const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: '_auth',
    sameSite: 'lax',
    path: '/',
    httpOnly: true,
    secrets: [process.env.SESSION_SECRET],
    secure: process.env.NODE_ENV === 'production',
  },
})

export const { getSession, commitSession, destroySession } = sessionStorage
```

## Strategy Instance

Now that we have everything set up, we can start implementing the Strategy Instance.

### 1. Implementing Strategy Instance

> [!IMPORTANT]
> A random 64-character hexadecimal string is required to generate the TOTP codes.
> You can use a site like https://www.grc.com/passwords.htm to generate a strong secret.

Add a 64-character hex string (0-9, A-F) as the `secret` property in your `.env` file. Example:
`ENCRYPTION_SECRET=928F416BAFC49B969E62052F00450B6E974B03E86DC6984D1FA787B7EA533227`

```ts
// app/lib/auth.server.ts
import { Authenticator } from 'remix-auth'
import { TOTPStrategy } from 'remix-auth-totp'
import { redirect } from 'react-router'
import { getSession, commitSession } from '~/lib/auth-session.server'

type User = {
  email: string
}

export const authenticator = new Authenticator<User>()

authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET,
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
> You can customize the cookie behavior by passing a `cookieOptions` property to the `TOTPStrategy` instance. Check [Customization](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) to learn more.

### 2: Implementing Strategy Logic

The Strategy Instance requires the following method: `sendTOTP`.

```ts
authenticator.use(
  new TOTPStrategy(
    {
      ...
      sendTOTP: async ({ email, code, magicLink }) => {
	// Send email with TOTP code.
	await sendAuthEmail({ email, code, magicLink })
      },
    },
    async ({ email }) => {},
  ),
)
```

### 3. Handling User Creation

The Strategy returns a `verify` method that allows handling our own logic. This includes creating the user, updating the session, etc.<br />

> [!TIP]
> When using Cloudflare D1, consider performing user lookups in the `action` or `loader` functions after committing the session. You can pass the `context` binding to a `findOrCreateUserByEmail` function to handle database operations.

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
      let user = await db.user.findFirst({ where: { email } })

      // Create a new user (if it doesn't exist).
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

Last but not least, we need to create the routes for the authentication flow.

We'll require the following routes:

- `login.tsx` - Handles the login form submission.
- `verify.tsx` - Handles the TOTP verification form submission.
- `logout.tsx` - Handles the logout.
- `dashboard.tsx` - Handles the authenticated route (optional).

### `login.tsx`

This route is used to handle the login form submission.

```tsx
// app/routes/login.tsx
import { redirect } from 'react-router'
import { useFetcher } from 'react-router'
import { getSession } from '~/lib/auth-session.server'
import { authenticator } from '~/lib/auth-server'

export async function loader({ request }: Route.LoaderArgs) {
  // Check for existing session.
  const session = await getSession(request.headers.get('Cookie'))
  const user = session.get('user')

  // If the user is already authenticated, redirect to your authenticated route.
  if (user) return redirect('/dashboard')

  return null
}

export async function action({ request }: Route.ActionArgs) {
  try {
    // Authenticate the user via TOTP (Form submission).
    return await authenticator.authenticate('TOTP', request)
  } catch (error) {
    // The error from TOTP includes the redirect Response with the cookie.
    if (error instanceof Response) {
      return error
    }

    // For other errors, return with error message.
    console.log('error', error)

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

This route is used to handle the TOTP verification form submission.

For the verify route, we are leveraging `@mjackson/headers` to parse the cookie. Created by Michael Jackson, the CO-Founder of Remix/React Router.

```tsx
// app/routes/verify.tsx
import { redirect, useLoaderData } from 'react-router'
import { Cookie } from '@mjackson/headers'
import { Link, useFetcher } from 'react-router'
import { useState } from 'react'
import { getSession } from '~/lib/auth-session.server'
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
    } catch (error: unknown) {
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

  const email = 'email' in loaderData ? loaderData.email : undefined
  const error = 'error' in loaderData ? loaderData.error : null
  const errors = fetcher.data?.error || error

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {/* Code Verification Form */}
      <fetcher.Form method="POST">
        <input
          required
          name="code"
          value={value}
          onChange={(e) => setValue(e.target.value)}
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

### `logout.tsx`

This route is used to destroy the session and redirect to the login page.

```tsx
// app/routes/logout.tsx
import { sessionStorage } from '~/lib/auth-session.server'
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

### `dashboard.tsx`

This route is used to display the authenticated user's dashboard (optional).

```tsx
// app/routes/dashboard.tsx
import { Link } from 'react-router'
import { getSession } from '~/lib/auth-session.server'
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

## Next Steps

🎉 Done! You've completed the basic setup.

For a complete implementation example, check out the [React Router v7 Starter Template](https://github.com/dev-xo/remix-auth-totp-starter).

## Configuration Options

The TOTP Strategy can be customized with various options to fit your needs. See the [customization documentation](https://github.com/dev-xo/remix-auth-totp/blob/main/docs/customization.md) for:

## Support

If you found **Remix Auth TOTP** helpful, please consider supporting it with a ⭐ [Star](https://github.com/dev-xo/remix-auth-totp).
