import { describe, test, expect, afterEach, vi } from 'vitest'
import { AuthorizationError } from 'remix-auth'
import { OTPStrategy } from '../src/index'
import { encrypt, generateOtp } from '../src/utils'
import {
  SECRET_ENV,
  HOST_URL,
  BASE_OPTIONS,
  OTP_DEFAULTS,
  sessionStorage,
  verify,
  storeCode,
  sendCode,
  validateCode,
  invalidateCode,
} from './utils'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Request (Re-send)', () => {
  test('Should call invalidateCode function.', async () => {
    verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    // OTP Code is not present in the form data.
    // formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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

  test('Should reassign form email with the one stored in Session.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'reassigned@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    let session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('email', 'example@gmail.com')
    // OTP Code is not present in the form data.
    // formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    session = await sessionStorage.getSession(result.headers.get('Set-Cookie') ?? '')

    // Asserts.
    expect(email).toMatch(session.data['auth:email'])
  })
})

describe('Generation', () => {
  test('Should throw an Error on missing required successRedirect option.', async () => {
    // Sets up testing data.
    const formData = new FormData()
    formData.append('email', 'example@gmail.com')

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
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
      new AuthorizationError('Missing required `successRedirect` property.'),
    )
  })

  test('Should throw an Error on missing email.', async () => {
    // Sets up testing data.
    const formData = new FormData()
    formData.append('email', '')

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
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
    expect(result).toEqual(new AuthorizationError('Email address is required.'))
  })

  test('Should throw an Error on invalid email.', async () => {
    // Sets up testing data.
    const formData = new FormData()
    formData.append('email', 'invalid-email')

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
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
    expect(result).toEqual(new AuthorizationError('Email address is not valid.'))
  })

  test('Should call storeCode function.', async () => {
    verify.mockImplementation(() => Promise.resolve({}))

    // Sets up testing data.
    const formData = new FormData()
    formData.append('email', 'example@gmail.com')

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
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
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
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
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
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
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        host: HOST_URL,
      },
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

describe('Authentication', () => {
  test('Should throw an Error on missing email from Session.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const session = await sessionStorage.getSession()
    const otp = generateOtp({ ...OTP_DEFAULTS })

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    expect(result).toEqual(new AuthorizationError('Missing required email address.'))
  })

  test('Should throw an Error on missing OTP code from Session.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const session = await sessionStorage.getSession()
    session.set('auth:email', email)

    const formData = new FormData()
    formData.append('code', 'invalid')

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    expect(result).toEqual(new AuthorizationError('Missing required OTP code.'))
  })

  test('Should call validateCode function.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    expect(result).toEqual(new AuthorizationError('Code not found.'))
  })

  test('Should throw an Error on inactive OTP code.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: false }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    expect(result).toEqual(new AuthorizationError('Code is no longer active.'))
  })

  test('Should throw an Error on max OTP code attempts.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true, attempts: 4 }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', 'invalid-code')

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    expect(result).toEqual(new AuthorizationError('Code cannot be used anymore.'))
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

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', 'invalid-code')

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    expect(result).toEqual(new AuthorizationError('Code does not match.'))
  })

  test('Should throw an Error on invalid OTP email.', async () => {
    verify.mockImplementation(() => Promise.resolve())

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

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

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
      new AuthorizationError('Code does not match the provided email address.'),
    )
  })

  test('Should call invalidateCode function.', async () => {
    verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    const session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    let session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    session = await sessionStorage.getSession(result.headers.get('Set-Cookie') ?? '')

    // Asserts.
    expect(session.data).toHaveProperty('user')
  })

  test('Should contain Location header pointing to provided successRedirect url.', async () => {
    verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

    // Sets up testing data.
    const email = 'example@gmail.com'
    const otp = generateOtp({ ...OTP_DEFAULTS })
    const otpEncrypted = await encrypt(JSON.stringify({ email, ...otp }), SECRET_ENV)

    // Updates mocked function.
    validateCode.mockImplementation(() =>
      Promise.resolve({ code: otpEncrypted, active: true }),
    )

    let session = await sessionStorage.getSession()
    session.set('auth:email', email)
    session.set('auth:otp', otpEncrypted)

    const formData = new FormData()
    formData.append('code', otp.code)

    // Creates Request.
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: {
        cookie: await sessionStorage.commitSession(session),
        host: HOST_URL,
      },
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
    session = await sessionStorage.getSession(result.headers.get('Set-Cookie') ?? '')

    // Asserts.
    expect(result.headers.get('Location')).toMatch('/account')
  })
})
