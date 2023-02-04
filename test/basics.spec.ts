import { describe, test, expect, vi } from 'vitest'
import { AuthorizationError } from 'remix-auth'
import { OTPStrategy } from '../src/index'
import { BASE_OPTIONS, SECRET_ENV, HOST_URL, sessionStorage } from './utils'

describe('Basics', () => {
  const verify = vi.fn()
  const storeCode = vi.fn()
  const sendCode = vi.fn()
  const validateCode = vi.fn()
  const invalidateCode = vi.fn()

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
})
