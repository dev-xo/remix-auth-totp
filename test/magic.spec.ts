import { describe, afterEach, test, expect, vi } from 'vitest'

import { AuthorizationError } from 'remix-auth'
import { OTPStrategy } from '../src/index'
import { encrypt, generateOtp, generateMagicLink } from '../src/utils'
import {
  BASE_OPTIONS,
  OTP_DEFAULTS,
  MAGIC_LINK_DEFAULTS,
  SECRET_ENV,
  HOST_URL,
  sessionStorage,
} from './utils'

describe('Magic Link', () => {
  const verify = vi.fn()
  const storeCode = vi.fn()
  const sendCode = vi.fn()
  const validateCode = vi.fn()
  const invalidateCode = vi.fn()

  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('Should throw an Error on invalid callbackPath.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)
    const otpEncryptedTwo = await encrypt(
      JSON.stringify({ email, ...otp }),
      SECRET_ENV,
    )
    const magicLink = generateMagicLink({
      ...MAGIC_LINK_DEFAULTS,
      callbackPath: '/invalid',
      param: 'code',
      code: otpEncryptedTwo,
      request: new Request(HOST_URL, { headers: { host: HOST_URL } }),
    })

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    // Creates Request.
    const request = new Request(`${magicLink}`, {
      method: 'GET',
      headers: {
        cookie: await sessionStorage.commitSession(session),
      },
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
        successRedirect: '/account',
      })
      .catch((error) => error)) as Response

    // Asserts.
    expect(result).toEqual(
      new AuthorizationError('Magic Link does not match the expected path.'),
    )
  })

  test('Should throw an Error on invalid OTP code.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)
    const otpEncryptedTwo = await encrypt(
      JSON.stringify({ email, ...otp }),
      SECRET_ENV,
    )
    const magicLink = generateMagicLink({
      ...MAGIC_LINK_DEFAULTS,
      param: 'code',
      code: otpEncryptedTwo,
      request: new Request(HOST_URL, { headers: { host: HOST_URL } }),
    })

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    // Creates Request.
    const request = new Request(`${magicLink}`, {
      method: 'GET',
      headers: {
        cookie: await sessionStorage.commitSession(session),
      },
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
        successRedirect: '/account',
      })
      .catch((error) => error)) as Response

    // Asserts.
    expect(result).toEqual(
      new AuthorizationError('Magic Link does not match the expected Signature.'),
    )
  })

  test('Should throw an Error on invalid OTP email.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)
    const magicLink = generateMagicLink({
      ...MAGIC_LINK_DEFAULTS,
      param: 'code',
      code: otpEncrypted,
      request: new Request(HOST_URL, { headers: { host: HOST_URL } }),
    })

    const databaseOtpEncrypted = await encrypt(
      JSON.stringify({ email: 'not-example@gmail.com', ...otp }),
      SECRET_ENV,
    )

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: databaseOtpEncrypted, active: true }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    // Creates Request.
    const request = new Request(`${magicLink}`, {
      method: 'GET',
      headers: {
        cookie: await sessionStorage.commitSession(session),
      },
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
        successRedirect: '/account',
      })
      .catch((error) => error)) as Response

    // Asserts.
    expect(result).toEqual(
      new AuthorizationError(
        'Magic Link does not match the provided email address.',
      ),
    )
  })

  test('Should contain Location header pointing to provided failureRedirect url.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)
    const otpEncryptedTwo = await encrypt(
      JSON.stringify({ email, ...otp }),
      SECRET_ENV,
    )
    const magicLink = generateMagicLink({
      ...MAGIC_LINK_DEFAULTS,
      param: 'code',
      code: otpEncryptedTwo,
      request: new Request(HOST_URL, { headers: { host: HOST_URL } }),
    })

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    // Creates Request.
    const request = new Request(`${magicLink}`, {
      method: 'GET',
      headers: {
        cookie: await sessionStorage.commitSession(session),
      },
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
        failureRedirect: '/login',
      })
      .catch((error) => error)) as Response

    // Asserts.
    expect(result.headers.get('Location')).toMatch('/login')
  })
})
