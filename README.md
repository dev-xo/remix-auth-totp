<br />
<p align="center">
  <img src="https://raw.githubusercontent.com/dev-xo/dev-xo/main/remix-auth-otp/assets/images/Intro-v4.png" alt="Logo">
</p>

<p align="center">
  A One-Time Password Authentication Strategy for Remix Auth
  <br>
  <br>
  <a href="https://remix-auth-otp.fly.dev">Live Demo</a>
  ·
  <a href="https://www.npmjs.com/package/remix-auth-otp">Package</a>
  ·
  <a href="https://twitter.com/DanielKanem">Author Twitter</a>
</p>

## Features

- **🥳 Easy to Setup**. The Strategy will handle the entire Authentication Flow for you.
- **🔐 Secure**. The OTP code is encrypted and signed with a Secret Key.
- **📚 One Source of Truth**. The database of your choice.
- **🛡 Bulletproof**. Written in strict TypeScript with a high test coverage.
- **🗂 Typed**. Ships with types included.
- **🚀 Built on top of Remix Auth**. An amazing authentication library for Remix.

## Live Demo

The template demo has been built to be really simple to use, being able to display all its provided features.<br />
Feel free to check and test it at [Remix Auth OTP Stack](https://remix-auth-otp.fly.dev)

## Getting Started

This Strategy uses a Passwordless Authentication Flow based on Email-Code validation.<br />

The user will receive an email with a code that will be used to authenticate itself.<br />
The code has just one use and it's valid for a short period of time, which makes it very secure.<br />

Let's see how we can implement this Strategy for our Remix App.

### Install the Package

First things first, we'll need to install the package.

```bash
npm install remix-auth-otp
```

### Database

We'll require a database to store the OTP codes. The OTP model will not be related to any User, this simplifies the process of generating the OTP code and makes it easier to be implemented to any database of your choice.

In this example we'll use Prisma ORM with a Sqlite database. As long as the database OTP Model looks like the following one, you are good to go.

```ts
// prisma/schema.prisma

/**
 * The OTP model only requires 3 fields: code, active and attempts.
 *
 * The `code` field will be a String and will be unique.
 * The `active` field will be a Boolean and will be set to false by default.
 * The `attempts` field will be an Int (Number) and will be set to 0 by default.
 * The `createdAt` and `updatedAt` fields are optional, and not required.
 */
model Otp {
  id String @id @default(cuid())

  code      String   @unique
  active    Boolean  @default(false)
  attempts  Int      @default(0)

  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

### Email Service

We'll require an Email Service to send the OTP code to the user. I'll recommend [Sendinblue](https://www.sendinblue.com), it's free and does not require Credit Card for registration, either use. Feel free to use any other Email Service of your choice like [Mailgun](https://www.mailgun.com/), [Sendgrid](https://sendgrid.com/), etc.

The goal is to have a sender function similar to the following one.

```ts
// app/services/email.server.ts
export interface SendEmailBody {
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
  return fetch(`https://any-email-service.com`, {
    method: 'post',
    headers: {
      Accept: 'application/json',
      'Api-Key': process.env.EMAIL_PROVIDER_API_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ ...body }),
  })
}
```

### Session Storage

We'll require to initialize a new Cookie Session Storage to work with.<br />
The Session will be used to store the user data and everything related to the Authentication Flow.

Create a file called `session.server.ts` wherever you want.<br />
Paste the following code and replace the `secrets` property with a strong string into your `.env` file.

```ts
// app/services/session.server.ts
import { createCookieSessionStorage } from '@remix-run/node'

export const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: '_session',
    sameSite: 'lax',
    path: '/',
    httpOnly: true,
    secrets: [process.env.SESSION_SECRET || 'STRONG_SECRET_PLEASE_CHANGE_ME'],
    secure: process.env.NODE_ENV === 'production',
  },
})

export const { getSession, commitSession, destroySession } = sessionStorage
```

### Creating the Strategy Instance

Now that we have the Database, Email Service and Session Storage ready, we can create the OTP Strategy Instance. I'll divide this in a few small steps.

**Step 1: Creating the Strategy Instance.**

Create a file called `auth.server.ts` wherever you want.<br />
Paste the following code and replace the `secret` property with a strong string into your `.env` file.

```ts
// app/services/auth.server.ts
import type { User } from '@prisma/client'

import { Authenticator } from 'remix-auth'
import { OTPStrategy } from 'remix-auth-otp'

import { db } from '~/db'
import { sessionStorage } from './session.server'
import { sendEmail } from './email.server'

export let authenticator = new Authenticator<User>(sessionStorage, {
  throwOnError: true,
})

authenticator.use(
  new OTPStrategy(
    {
      secret: 'STRONG_SECRET_PLEASE_CHANGE_ME',
      storeCode: async (code) => {},
      sendCode: async ({ email, code, user, form }) => {},
      validateCode: async (code) => {},
      invalidateCode: async (code) => {},
    },
    async ({ email, code, form }) => {},
  ),
)
```

**Step 2: Setting Up the Strategy Options.**

The Strategy Instance requires the following options.
It's important to note that `storeCode`, `sendCode`, `validateCode` and `invalidateCode` are all required.

> Each of these functions can be extracted to a separate file, but for the sake of simplicity, we'll keep them in the same one.

```ts
// app/services/auth.server.ts
authenticator.use(
  new OTPStrategy({
    /**
     * Stores encrypted OTP code in database.
     * It should return a Promise<void>.
     */
    storeCode: async (code) => {
      await db.otp.create({
        data: {
          code: code,
          active: true,
        },
      })
    },

    /**
     * Sends the OTP code to the user.
     * It should return a Promise<void>.
     */
    sendCode: async ({ email, code, user, form }) => {
      const sender = { name: 'Remix Auth', email: 'localhost@example.com' }
      const to = [{ email }]
      const subject = `Here's your OTP Code.`
      const htmlContent = `
          <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
          <html>
            <head>
              <meta http-equiv="Content-Type" content="text/html charset=UTF-8" />
            </head>
            <body>
              <h1>Code: ${code}</h1>
            </body>
          </html>
          `

      // Calls the provider sender email function.
      await sendEmail({ sender, to, subject, htmlContent })
    },

    /**
     * Validates the OTP code.
     * It should return a Promise<{ code: string, active: boolean, attempts: number }>.
     */
    validateCode: async (code) => {
      const otp = await db.otp.findUnique({
        where: {
          code: code,
        },
      })
      if (!otp) throw new Error('OTP code not found.')

      // This will be used by the internal Strategy
      // methods to validate the code.
      return {
        code: otp.code,
        active: otp.active,
        attempts: otp.attempts,
      }
    },

    /**
     * Invalidates the OTP code.
     * It should return a Promise<void>.
     */
    invalidateCode: async (code, active, attempts) => {
      await db.otp.update({
        where: {
          code: code,
        },
        // This will be used by the internal Strategy
        // methods to invalidate / update the code.
        data: {
          active: active,
          attempts: attempts,
        },
      })
    },
    async ({ email, code, form }) => {},
  }),
)
```

All of this database methods should be replaced and adapted with the ones provided by your database.

**Step 3: Creating the user and returning it.**

The Strategy has a verify function that will be called before authenticating the user. This should return the user data that will be stored in Session.

```ts
authenticator.use(
  new OTPStrategy(
    {
      // We've already set up the options.
      // secret: 'STRONG_SECRET_PLEASE_CHANGE_ME',
      // storeCode: async (code) => {},
      // ...
    },
    async ({ email, code, form }) => {
      // Gets user from database.
      // This is the right place to create a new user (if not exists).
      const user = await db.user.findFirst({
        where: {
          email: email,
        },
      })

      if (!user) {
        const newUser = await db.user.create({
          data: {
            email: email,
          },
        })
        if (!newUser) throw new Error('Unable to create new user.')

        return newUser
      }

      // Returns the user.
      return user
    },
  ),
)
```

And that's it! Feel free to check the [Example Code](https://github.com/dev-xo/remix-auth-otp-stack) implementation, in case you wanna use it as a reference.

### Auth Routes

Last but not least, we'll need to create the routes that will handle the Authentication Flow.
Create the following files inside the `app/routes` folder.

```tsx
// app/routes/login.tsx
import type { DataFunctionArgs } from '@remix-run/node'
import { json } from '@remix-run/node'
import { Form, useLoaderData } from '@remix-run/react'

import { authenticator } from '~/services/auth.server'
import { getSession, commitSession } from '~/services/session.server'

export async function loader({ request }: DataFunctionArgs) {
  const user = await authenticator.isAuthenticated(request, {
    successRedirect: '/account',
  })

  /**
   * Gets the Session and the required data from it.
   */
  const session = await getSession(request.headers.get('Cookie'))
  const hasSentEmail = session.has('auth:otp')

  const email = session.get('auth:email')
  const error = session.get(authenticator.sessionErrorKey)

  /**
   * Commits Session to clear any possible error message.
   */
  return json(
    { user, hasSentEmail, email, error },
    {
      headers: {
        'Set-Cookie': await commitSession(session),
      },
    },
  )
}

export async function action({ request }: DataFunctionArgs) {
  await authenticator.authenticate('OTP', request, {
    /**
     * Setting `successRedirect` it's required.
     *
     * User is not authenticated yet.
     * We want to render the verify code form.
     *
     * Feel free to redirect to any other page like /verify-code.
     */
    successRedirect: '/login',

    /**
     * Setting `failureRedirect` it's required.
     *
     * We want to display any possible error message.
     * Otherwise the ErrorBoundary / CatchBoundary will be triggered.
     */
    failureRedirect: '/login',
  })
}

export default function Login() {
  let { user, hasSentEmail, email, error } = useLoaderData<typeof loader>()

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', lineHeight: '1.4' }}>
      {/* Displaying possible error messages. */}
      {error && <strong>Error: {error.message}</strong>}

      {/* Displaying the form that sends the email. */}
      {!user && !hasSentEmail && (
        <Form method="post" autoComplete="off">
          <label htmlFor="email">Email</label>
          <input name="email" placeholder="Insert email .." required />

          <button type="submit">Send Code</button>
        </Form>
      )}

      {/* Displaying the form that verifies the code. */}
      {hasSentEmail && (
        <div style={{ display: 'flex', flexDirection: 'row' }}>
          <Form method="post" autoComplete="off">
            <label htmlFor="code">Code</label>
            <input type="text" name="code" placeholder="Insert code .." required />

            <button type="submit">Continue</button>
          </Form>

          {/* Displaying the form that requests a new code. */}
          {/* Email input is not required, the email is already in Session. */}
          <Form method="post" autoComplete="off">
            <button type="submit">Request new Code</button>
          </Form>
        </div>
      )}
    </div>
  )
}
```

```tsx
// app/routes/account.tsx
import type { DataFunctionArgs } from '@remix-run/node'

import { json } from '@remix-run/node'
import { Form, useLoaderData } from '@remix-run/react'
import { authenticator } from '~/services/auth.server'

export async function loader({ request }: DataFunctionArgs) {
  const user = await authenticator.isAuthenticated(request, {
    failureRedirect: '/',
  })

  return json({ user })
}

export default function Account() {
  let { user } = useLoaderData<typeof loader>()

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', lineHeight: '1.4' }}>
      <h1>{user ? `Welcome ${user.email}` : 'Authenticate'}</h1>

      <Form action="/logout" method="post">
        <button>Log Out</button>
      </Form>
    </div>
  )
}
```

```tsx
// app/routes/logout.tsx
import type { DataFunctionArgs } from '@remix-run/node'
import { authenticator } from '~/services/auth.server'

export async function action({ request }: DataFunctionArgs) {
  return await authenticator.logout(request, { redirectTo: '/' })
}
```

## Options and Customization

The Strategy includes a few options that can be customized.

### Email Validation

The email validation function will validate every email against the regular expression `/.+@.+/`.<br />
You can customize it by passing a function called `validateEmail` to the OTPStrategy Instance.

This can be used to verify that the provided email is not a disposable one.

```ts
authenticator.use(
  new OTPStrategy({
    validateEmail: async (email) => {
      // Do something with the email.
    },
    // storeCode: async (code) => {},
    // sendCode: async ({ email, code, user, form }) => {},
    // ...
  }),
)
```

### Code Generation

The Code output can be customized by passing an Object called `codeGeneration` to the OTPStrategy Instance.

Here are its available options:

```ts
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

authenticator.use(
  new OTPStrategy({
    codeGeneration: {
      length: 12,
      expiresAt: 1000 * 60 * 5, // 5 minutes in milliseconds.
      // ... other options.
    },
    // storeCode: async (code) => {},
    // sendCode: async ({ email, code, user, form }) => {},
    // ...
  }),
)
```

### More Options

The Strategy supports a few more optional configuration options you can set.<br />

```ts
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
```

## Support

If you find this module useful, support it with a [Star ⭐](https://github.com/dev-xo/remix-auth-otp)<br />
It helps the repository grow and gives me motivation to keep working on it. Thank you!

## License

Licensed under the [MIT license](https://github.com/dev-xo/stripe-stack/blob/main/LICENSE).
