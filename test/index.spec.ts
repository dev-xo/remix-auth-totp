import { describe, afterEach, test, expect, vi } from 'vitest'

import { createCookieSessionStorage } from '@remix-run/node'
import { AuthenticateOptions, AuthorizationError } from 'remix-auth'
import { OTPStrategy } from '../src/index'
import { encrypt, generateOtp } from '../src/utils'

// Constants.
const BASE_URL = 'http://localhost:3000'
const SECRET_ENV = 'SECRET'
const OTP_DEFAULTS = {
  expiresAt: 1000 * 60 * 15,
  length: 6,
  digits: false,
  lowerCaseAlphabets: false,
  upperCaseAlphabets: true,
  specialChars: false,
}

// Authenticate Options.
const BASE_OPTIONS: AuthenticateOptions = {
  name: 'OTP',
  sessionKey: 'user',
  sessionErrorKey: 'error',
  sessionStrategyKey: 'strategy',
}

// Session Storage.
const sessionStorage = createCookieSessionStorage({
  cookie: { secrets: ['SESSION_SECRET_KEY'] },
})

describe('OTP Strategy', () => {
  // Mocks and Hooks.
  const verify = vi.fn()
  const storeCode = vi.fn()
  const sendCode = vi.fn()
  const validateCode = vi.fn()
  const invalidateCode = vi.fn()

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('[ Basics ]', () => {
    test('Should contain the name of the Strategy.', async () => {
      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      // Asserts.
      expect(strategy.name).toBe('OTP')
    })

    test('Should throw an Error on missing required secret option.', async () => {
      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(
        new AuthorizationError('Missing required secret option.'),
      )
    })

    test('Should throw an Error on missing required successRedirect option.', async () => {
      // Sets up testing data.
      const formData = new FormData()
      formData.append('email', 'example@gmail.com')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(
        new AuthorizationError('Missing required successRedirect option.'),
      )
    })
  })

  describe('[ Request new OTP Code ]', () => {
    test('Should call invalidateCode function.', async () => {
      verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true }),
      )

      const formData = new FormData()
      // OTP Code is not present in the form data.
      // formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(invalidateCode).toHaveBeenCalledTimes(1)
    })

    test('Should reassign form email with the one from the Session.', async () => {
      verify.mockImplementation(() => Promise.resolve())

      // Sets up testing data.
      const email = 'reassigned@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      let session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true }),
      )

      const formData = new FormData()
      formData.append('email', 'example@gmail.com')
      // OTP Code is not present in the form data.
      // formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      // Gets values from Session.
      session = await sessionStorage.getSession(
        result.headers.get('Set-Cookie') ?? '',
      )

      // Asserts.
      expect(email).toMatch(session.data['auth:email'])
    })
  })

  describe('[ Authentication 1st - Without OTP Code ]', () => {
    test('Should throw an Error on missing email.', async () => {
      // Sets up testing data.
      const formData = new FormData()
      formData.append('email', '')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(new AuthorizationError('Missing required email field.'))
    })

    test('Should throw an Error on invalid email.', async () => {
      // Sets up testing data.
      const formData = new FormData()
      formData.append('email', 'invalid-email')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(new AuthorizationError('Invalid email address.'))
    })

    test('Should call storeCode function.', async () => {
      verify.mockImplementation(() => Promise.resolve({}))

      // Sets up testing data.
      const formData = new FormData()
      formData.append('email', 'example@gmail.com')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(storeCode).toHaveBeenCalledTimes(1)
    })

    test('Should call sendCode function.', async () => {
      verify.mockImplementation(() => Promise.resolve({}))

      // Sets up testing data.
      const formData = new FormData()
      formData.append('email', 'example@gmail.com')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(sendCode).toHaveBeenCalledTimes(1)
    })

    test('Should contain auth:email and auth:otp properties in Session.', async () => {
      verify.mockImplementation(() => Promise.resolve({}))

      // Sets up testing data.
      const formData = new FormData()
      formData.append('email', 'example@gmail.com')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      // Gets values from Session.
      const session = await sessionStorage.getSession(
        result.headers.get('Set-Cookie') ?? '',
      )

      // Asserts.
      expect(session.data).toHaveProperty('auth:email')
      expect(session.data).toHaveProperty('auth:otp')
    })

    test('Should contain Location header pointing to provided successRedirect url.', async () => {
      verify.mockImplementation(() => Promise.resolve({}))

      // Sets up testing data.
      const formData = new FormData()
      formData.append('email', 'example@gmail.com')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          successRedirect: '/verify',
        })
        .catch((error) => error)) as Response

      // Asserts.
      expect(result.headers.get('Location')).toMatch('/verify')
    })
  })

  describe('[ Authentication 2nd - With OTP Code ]', () => {
    test('Should throw an Error on missing email from Session.', async () => {
      verify.mockImplementation(() => Promise.resolve())

      // Sets up testing data.
      const session = await sessionStorage.getSession()
      const otp = generateOtp({ ...OTP_DEFAULTS })

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(
        new AuthorizationError('Missing required email from Session.'),
      )
    })

    test('Should call validateCode function.', async () => {
      verify.mockImplementation(() => Promise.resolve())

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(validateCode).toHaveBeenCalledTimes(1)
    })

    test('Should throw an Error on missing OTP code from database.', async () => {
      verify.mockImplementation(() => Promise.resolve())
      validateCode.mockImplementation(() => Promise.resolve(null))

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(new AuthorizationError('OTP code not found.'))
    })

    test('Should throw an Error on inactive OTP code.', async () => {
      verify.mockImplementation(() => Promise.resolve())

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: false }),
      )

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(new AuthorizationError('Code is not active.'))
    })

    test('Should throw an Error on max OTP code attempts.', async () => {
      verify.mockImplementation(() => Promise.resolve())

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true, attempts: 4 }),
      )

      const formData = new FormData()
      formData.append('code', 'invalid-code')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(
        new AuthorizationError('Code has reached maximum attempts.'),
      )
    })

    test('Should throw an Error on expired OTP code.', async () => {
      verify.mockImplementation(() => Promise.resolve())

      // Sets up testing data.
      const email = 'example@gmail.com'
      const expiresAt = new Date(Date.now() - 1000 * 60 * 15)
      const expiredCreatedAt = new Date(expiresAt).toISOString()
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, code: otp.code, createdAt: expiredCreatedAt }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true }),
      )

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(new AuthorizationError('Code has expired.'))
    })

    test('Should throw an Error on invalid OTP code.', async () => {
      verify.mockImplementation(() => Promise.resolve())

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true }),
      )

      const formData = new FormData()
      formData.append('code', 'invalid-code')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(new AuthorizationError('Code is not valid.'))
    })

    test('Should throw an Error on invalid OTP emails', async () => {
      verify.mockImplementation(() => Promise.resolve())

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const databaseOtpEncrypted = await encrypt(
        JSON.stringify({ email: 'not-example@gmail.com', ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: databaseOtpEncrypted, active: true }),
      )

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)

      // Asserts.
      expect(result).toEqual(
        new AuthorizationError('Code does not match provided email address.'),
      )
    })

    test('Should call invalidateCode function.', async () => {
      verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true }),
      )

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          successRedirect: '/account',
        })
        .catch((error) => error)

      // Asserts.
      expect(invalidateCode).toHaveBeenCalledTimes(1)
    })

    test('Should call invalidateCode function on invalid OTP code.', async () => {
      verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      const session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true }),
      )

      const formData = new FormData()
      formData.append('code', 'invalid-code')

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          successRedirect: '/account',
        })
        .catch((error) => error)

      // Asserts.
      expect(invalidateCode).toHaveBeenCalledTimes(1)
    })

    test('Should contain user property in Session.', async () => {
      verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      let session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true }),
      )

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      // Gets values from Session.
      session = await sessionStorage.getSession(
        result.headers.get('Set-Cookie') ?? '',
      )

      // Asserts.
      expect(session.data).toHaveProperty('user')
    })

    test('Should contain Location header pointing to provided successRedirect url.', async () => {
      verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

      // Sets up testing data.
      const email = 'example@gmail.com'
      const otp = generateOtp({ ...OTP_DEFAULTS })
      const otpEncrypted = await encrypt(
        JSON.stringify({ email, ...otp }),
        SECRET_ENV,
      )

      let session = await sessionStorage.getSession()
      session.set('auth:email', email)
      session.set('auth:otp', otpEncrypted)

      // Updates mocked function.
      validateCode.mockImplementation(() =>
        Promise.resolve({ code: otpEncrypted, active: true }),
      )

      const formData = new FormData()
      formData.append('code', otp.code)

      // Creates Request.
      const request = new Request(`${BASE_URL}`, {
        method: 'POST',
        headers: { cookie: await sessionStorage.commitSession(session) },
        body: formData,
      })

      // Initializes Strategy.
      const strategy = new OTPStrategy(
        { secret: SECRET_ENV, storeCode, sendCode, validateCode, invalidateCode },
        verify,
      )

      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...BASE_OPTIONS,
          successRedirect: '/account',
        })
        .catch((error) => error)) as Response

      // Gets values from Session.
      session = await sessionStorage.getSession(
        result.headers.get('Set-Cookie') ?? '',
      )

      // Asserts.
      expect(result.headers.get('Location')).toMatch('/account')
    })
  })
})
