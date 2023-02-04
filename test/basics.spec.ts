import { test, expect, afterEach, vi } from 'vitest'
import { AuthorizationError } from 'remix-auth'
import { OTPStrategy } from '../src/index'
import {
  SECRET_ENV,
  HOST_URL,
  BASE_OPTIONS,
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
  const request = new Request(`${HOST_URL}`, {
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
    new AuthorizationError(
      'Missing required `secret` option from OTPStrategy constructor.',
    ),
  )
})

test('Should throw a custom Error message.', async () => {
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
    {
      secret: SECRET_ENV,
      storeCode,
      sendCode,
      validateCode,
      invalidateCode,
      customErrors: {
        requiredEmail: 'Custom error message for required email.',
      },
    },
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
    new AuthorizationError('Custom error message for required email.'),
  )
})
