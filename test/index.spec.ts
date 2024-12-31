import type { SendTOTPOptions, TOTPStrategyOptions } from '../src/index'

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import invariant from 'tiny-invariant'

import { TOTPStrategy } from '../src/index'
import { asJweKey, generateMagicLink } from '../src/utils'
import { STRATEGY_NAME, FORM_FIELDS, ERRORS } from '../src/constants'

import {
  SECRET_ENV,
  HOST_URL,
  TOTP_GENERATION_DEFAULTS,
  DEFAULT_EMAIL,
  MAGIC_LINK_PATH,
} from './utils'
import { Cookie, SetCookie } from '@mjackson/headers'

/**
 * Mocks.
 */
const verify = vi.fn()
const sendTOTP = vi.fn()

const BASE_STRATEGY_OPTIONS: Omit<
  TOTPStrategyOptions,
  'successRedirect' | 'failureRedirect'
> = {
  secret: SECRET_ENV,
  sendTOTP,
  magicLinkPath: MAGIC_LINK_PATH,
}

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('[ Basics ]', () => {
  test('Should contain the name of the Strategy.', async () => {
    const strategy = new TOTPStrategy(
      {
        ...BASE_STRATEGY_OPTIONS,
        successRedirect: '/verify',
        failureRedirect: '/login',
      },
      verify,
    )
    expect(strategy.name).toBe(STRATEGY_NAME)
  })

  test('Should throw an Error on missing required secret option.', async () => {
    const strategy = new TOTPStrategy(
      // @ts-expect-error - Error is expected since missing secret option.
      {
        sendTOTP,
        successRedirect: '/verify',
        failureRedirect: '/login',
      },
      verify,
    )
    const request = new Request(`${HOST_URL}/login`, {
      method: 'POST',
    })
    await expect(() => strategy.authenticate(request)).rejects.toThrow(
      ERRORS.REQUIRED_ENV_SECRET,
    )
  })

  test('Should throw an Error on missing required successRedirect option.', async () => {
    const strategy = new TOTPStrategy(
      // @ts-expect-error - Error is expected since missing successRedirect
      {
        ...BASE_STRATEGY_OPTIONS,
        failureRedirect: '/login',
      },
      verify,
    )
    const request = new Request(`${HOST_URL}/login`, {
      method: 'POST',
    })
    await expect(() => strategy.authenticate(request)).rejects.toThrow(
      ERRORS.REQUIRED_SUCCESS_REDIRECT_URL,
    )
  })

  test('Should throw an Error on missing required failureRedirect option.', async () => {
    const strategy = new TOTPStrategy(
      // @ts-expect-error - Error is expected since missing failureRedirect
      {
        ...BASE_STRATEGY_OPTIONS,
        successRedirect: '/verify',
      },
      verify,
    )
    const request = new Request(`${HOST_URL}/login`, {
      method: 'POST',
    })
    await expect(() => strategy.authenticate(request)).rejects.toThrow(
      ERRORS.REQUIRED_FAILURE_REDIRECT_URL,
    )
  })
})

describe('[ TOTP ]', () => {
  describe('Generate/Send TOTP', () => {
    test('Should generate/send TOTP for form email.', async () => {
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
        expect(options.request).toBeInstanceOf(Request)
        expect(options.formData).toBeInstanceOf(FormData)
      })
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        },
        verify,
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          const params = new URLSearchParams(raw!)
          const email = params.get('email')
          const totpRaw = params.get('totp')
          expect(email).toBe(DEFAULT_EMAIL)
          expect(totpRaw).toBeDefined()
        } else throw reason
      })

      expect(sendTOTP).toHaveBeenCalledTimes(1)
    })

    test('Should generate/send TOTP for form email with application form data.', async () => {
      const APP_FORM_FIELD = 'via'
      const APP_FORM_VALUE = 'whatsapp'
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
        expect(options.request).toBeInstanceOf(Request)
        expect(options.formData).toBeInstanceOf(FormData)
        expect(options.formData.get(APP_FORM_FIELD)).toBe(APP_FORM_VALUE)
      })
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        },
        verify,
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      formData.append(APP_FORM_FIELD, APP_FORM_VALUE)
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          const params = new URLSearchParams(raw!)
          const email = params.get('email')
          const totpRaw = params.get('totp')
          expect(email).toBe(DEFAULT_EMAIL)
          expect(totpRaw).toBeDefined()
        } else throw reason
      })

      expect(sendTOTP).toHaveBeenCalledTimes(1)
    })

    test('Should generate/send TOTP for form email ignoring form totp code.', async () => {
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
        expect(options.request).toBeInstanceOf(Request)
        expect(options.formData).toBeInstanceOf(FormData)
      })
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        },
        verify,
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      formData.append(FORM_FIELDS.CODE, '123456')
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toMatch('/verify')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          const params = new URLSearchParams(raw!)
          const email = params.get('email')
          const totpRaw = params.get('totp')
          expect(email).toBe(DEFAULT_EMAIL)
          expect(totpRaw).toBeDefined()
        } else throw reason
      })

      expect(sendTOTP).toHaveBeenCalledTimes(1)
    })

    test('Should generate/send TOTP for form email ignoring session email.', async () => {
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        },
        verify,
      )
      const formDataToPopulateSessionEmail = new FormData()
      formDataToPopulateSessionEmail.append(FORM_FIELDS.EMAIL, 'email@session.com')
      const requestToPopulateSessionEmail = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formDataToPopulateSessionEmail,
      })
      let firstTOTP: string | undefined
      let firstResponseCookie: string | undefined
      await strategy.authenticate(requestToPopulateSessionEmail).catch((reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('email')).toBe('email@session.com')
          const totpRaw = params.get('totp')
          expect(totpRaw).toBeDefined()
          firstTOTP = totpRaw ?? undefined
          firstResponseCookie = setCookieHeader
        } else {
          throw reason
        }
      })

      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).not.toBe('')
      })

      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        headers: { cookie: firstResponseCookie ?? '' },
        body: formData,
      })
      await strategy.authenticate(request).catch((reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')

          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()

          const params = new URLSearchParams(raw!)
          expect(params.get('email')).toBe(DEFAULT_EMAIL)
          const newTOTP = params.get('totp')
          expect(newTOTP).toBeDefined()
          expect(newTOTP).not.toEqual(firstTOTP)
        } else {
          throw reason
        }
      })

      expect(sendTOTP).toHaveBeenCalledTimes(2)
    })

    test('Should generate/send TOTP for empty form data with session email.', async () => {
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
        expect(options.request).toBeInstanceOf(Request)
        expect(options.formData).toBeInstanceOf(FormData)
      })
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        },
        verify,
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      const requestToPopulate = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      let firstTOTP: string | undefined
      let firstCookieHeader: string | undefined
      await strategy.authenticate(requestToPopulate).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          const params = new URLSearchParams(raw!)
          expect(params.get('email')).toBe(DEFAULT_EMAIL)
          const totpRaw = params.get('totp')
          expect(totpRaw).toBeDefined()
          firstTOTP = totpRaw ?? undefined
          firstCookieHeader = setCookieHeader
        } else throw reason
      })
      if (!firstTOTP) throw new Error('Undefined session.')
      const emptyFormRequest = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        headers: {
          cookie: firstCookieHeader ?? '',
        },
        body: new FormData(),
      })
      await strategy.authenticate(emptyFormRequest).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('email')).toBe(DEFAULT_EMAIL)
          const newTOTP = params.get('totp')
          expect(newTOTP).toBeDefined()
          expect(newTOTP).not.toEqual(firstTOTP)
        } else throw reason
      })
      expect(sendTOTP).toHaveBeenCalledTimes(2)
    })

    test('Should generate/send TOTP for application form data with session email.', async () => {
      const APP_FORM_FIELD = 'via'
      const APP_FORM_VALUE = 'whatsapp'
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
        expect(options.request).toBeInstanceOf(Request)
        expect(options.formData).toBeInstanceOf(FormData)
        expect(options.formData.get(APP_FORM_FIELD)).toBe(APP_FORM_VALUE)
      })
      let firstTOTP: string | undefined
      let firstCookieHeader: string | undefined
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        },
        verify,
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      formData.append(APP_FORM_FIELD, APP_FORM_VALUE)
      const requestToPopulateEmail = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      await strategy.authenticate(requestToPopulateEmail).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('email')).toBe(DEFAULT_EMAIL)
          const totpRaw = params.get('totp')
          expect(totpRaw).toBeDefined()
          firstTOTP = totpRaw ?? undefined
          firstCookieHeader = setCookieHeader
        } else throw reason
      })
      const appFormData = new FormData()
      appFormData.append(APP_FORM_FIELD, APP_FORM_VALUE)
      const appFormRequest = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        headers: {
          cookie: firstCookieHeader ?? '',
        },
        body: appFormData,
      })
      await strategy.authenticate(appFormRequest).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('email')).toBe(DEFAULT_EMAIL)
          const newTOTP = params.get('totp')
          expect(newTOTP).toBeDefined()
          expect(newTOTP).not.toEqual(firstTOTP)
        } else throw reason
      })
      expect(sendTOTP).toHaveBeenCalledTimes(2)
    })

    test('Should failure redirect on invalid email.', async () => {
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        },
        verify,
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, '@invalid-email')
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })

      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/login')

          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()

          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.INVALID_EMAIL)
        } else throw reason
      })
    })

    test('Should failure redirect on invalid email with custom error.', async () => {
      const CUSTOM_ERROR = 'TEST: Invalid email.'
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
          customErrors: {
            invalidEmail: CUSTOM_ERROR,
          },
        },
        verify,
      )

      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, '@invalid-email')
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })

      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/login')

          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()

          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(CUSTOM_ERROR)
        } else throw reason
      })
    })

    test('Should failure redirect when custom validateEmail returns false.', async () => {
      const ERROR_MESSAGE = 'TEST: Invalid email.'
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
          customErrors: {
            invalidEmail: ERROR_MESSAGE,
          },
          validateEmail: async () => false,
        },
        verify,
      )

      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, '@invalid-email')
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })

      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/login')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERROR_MESSAGE)
        } else throw reason
      })
    })

    test('Should failure redirect on missing email.', async () => {
      const strategy = new TOTPStrategy(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        },
        verify,
      )
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: new FormData(),
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/login')
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.REQUIRED_EMAIL)
        } else throw reason
      })
    })
  })

  describe('Validate TOTP', () => {
    async function setupGenerateSendTOTP(
      totpStrategyOptions: Partial<TOTPStrategyOptions> = {},
    ) {
      const user = { name: 'Joe Schmoe' }
      let sendTOTPOptions: SendTOTPOptions | undefined
      let totpCookie: string | undefined

      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        sendTOTPOptions = options
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
        expect(options.magicLink).toBe(
          `${HOST_URL}${MAGIC_LINK_PATH}?code=${options.code}`,
        )
      })

      const strategy = new TOTPStrategy<typeof user>(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
          ...totpStrategyOptions,
        },
        async ({ email, formData, request }) => {
          expect(email).toBe(DEFAULT_EMAIL)
          expect(request).toBeInstanceOf(Request)
          if (request.method === 'POST') {
            expect(formData).toBeInstanceOf(FormData)
          } else {
            expect(formData).not.toBeDefined()
          }
          return Promise.resolve(user)
        },
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe('/verify')
          totpCookie = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(totpCookie)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('email')).toBe(DEFAULT_EMAIL)
          expect(params.get('totp')).toBeDefined()
        } else throw reason
      })

      expect(sendTOTP).toHaveBeenCalledTimes(1)
      expect(sendTOTPOptions).toBeDefined()
      invariant(sendTOTPOptions, 'Undefined sendTOTPOptions')
      expect(totpCookie).toBeDefined()
      invariant(totpCookie, 'Undefined cookie')
      return { strategy, sendTOTPOptions, totpCookie, user }
    }

    // test('Should successfully validate totp code.', async () => {
    //   const { sendTOTPOptions, totpCookie, user } = await setupGenerateSendTOTP()
    //   const strategy = new TOTPStrategy<typeof user>(
    //     {
    //       ...BASE_STRATEGY_OPTIONS,
    //       successRedirect: '/account',
    //       failureRedirect: '/login',
    //     },
    //     async ({ email, formData, request }) => {
    //       expect(email).toBe(DEFAULT_EMAIL)
    //       expect(request).toBeInstanceOf(Request)
    //       if (request.method === 'POST') {
    //         expect(formData).toBeInstanceOf(FormData)
    //       } else {
    //         expect(formData).not.toBeDefined()
    //       }
    //       return Promise.resolve(user)
    //     },
    //   )
    //   const formData = new FormData()
    //   formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
    //   const request = new Request(`${HOST_URL}/verify`, {
    //     method: 'POST',
    //     headers: {
    //       cookie: totpCookie,
    //     },
    //     body: formData,
    //   })
    //   await strategy.authenticate(request).catch(async (reason) => {
    //     if (reason instanceof Response) {
    //       expect(reason.status).toBe(302)
    //       expect(reason.headers.get('location')).toBe(`/account`)
    //       const setCookieHeader = reason.headers.get('set-cookie') ?? ''
    //       const cookie = new Cookie(setCookieHeader)
    //       const raw = cookie.get('_totp')
    //       expect(raw).toBeDefined()
    //       const params = new URLSearchParams(raw!)
    //       expect(params.get('email')).toBeNull()
    //       expect(params.get('totp')).toBeNull()
    //       expect(params.get('error')).toBeNull()
    //     } else throw reason
    //   })
    // })

    test('Should failure redirect on invalid totp code.', async () => {
      const { user, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      const strategy = new TOTPStrategy<typeof user>(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/verify',
        },
        async ({ email, formData, request }) => {
          expect(email).toBe(DEFAULT_EMAIL)
          expect(request).toBeInstanceOf(Request)
          if (request.method === 'POST') {
            expect(formData).toBeInstanceOf(FormData)
          } else {
            expect(formData).not.toBeDefined()
          }
          return Promise.resolve(user)
        },
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code + 'INVALID')
      const request = new Request(`${HOST_URL}/verify`, {
        method: 'POST',
        headers: {
          cookie: totpCookie,
        },
        body: formData,
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/verify`)
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()

          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.INVALID_TOTP)
        } else throw reason
      })
    })

    test('Should failure redirect on invalid totp code with custom error.', async () => {
      const CUSTOM_ERROR = 'TEST: invalid totp code'
      const { user, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      const strategy = new TOTPStrategy<typeof user>(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/verify',
          customErrors: {
            invalidTotp: CUSTOM_ERROR,
          },
        },
        async ({ email, formData, request }) => {
          expect(email).toBe(DEFAULT_EMAIL)
          expect(request).toBeInstanceOf(Request)
          if (request.method === 'POST') {
            expect(formData).toBeInstanceOf(FormData)
          } else {
            expect(formData).not.toBeDefined()
          }
          return Promise.resolve(user)
        },
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code + 'INVALID')
      const request = new Request(`${HOST_URL}/verify`, {
        method: 'POST',
        headers: {
          cookie: totpCookie,
        },
        body: formData,
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/verify`)
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(CUSTOM_ERROR)
        } else throw reason
      })
    })

    test('Should failure redirect on invalid and max TOTP attempts.', async () => {
      let { user, totpCookie, sendTOTPOptions } = await setupGenerateSendTOTP()
      const strategy = new TOTPStrategy<typeof user>(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/verify',
        },
        async ({ email, formData, request }) => {
          expect(email).toBe(DEFAULT_EMAIL)
          expect(request).toBeInstanceOf(Request)
          if (request.method === 'POST') {
            expect(formData).toBeInstanceOf(FormData)
          } else {
            expect(formData).not.toBeDefined()
          }
          return Promise.resolve(user)
        },
      )
      for (let i = 0; i <= TOTP_GENERATION_DEFAULTS.maxAttempts; i++) {
        const formData = new FormData()
        formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code + 'INVALID')
        const request = new Request(`${HOST_URL}/verify`, {
          method: 'POST',
          headers: {
            cookie: totpCookie,
          },
          body: formData,
        })
        await strategy.authenticate(request).catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe(`/verify`)
            const setCookieHeader = reason.headers.get('set-cookie') ?? ''
            totpCookie = setCookieHeader
            const cookie = new Cookie(setCookieHeader)
            const raw = cookie.get('_totp')
            expect(raw).toBeDefined()
            const params = new URLSearchParams(raw!)
            expect(params.get('error')).toBe(
              i < TOTP_GENERATION_DEFAULTS.maxAttempts
                ? ERRORS.INVALID_TOTP
                : ERRORS.EXPIRED_TOTP,
            )
            if (i >= TOTP_GENERATION_DEFAULTS.maxAttempts) {
              expect(params.get('totp')).toBeNull()
            }
          } else throw reason
        })
      }
    })

    test('Should failure redirect on expired totp code.', async () => {
      const { user, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      const strategy = new TOTPStrategy<typeof user>(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/verify',
        },
        async ({ email, formData, request }) => {
          expect(email).toBe(DEFAULT_EMAIL)
          expect(request).toBeInstanceOf(Request)
          if (request.method === 'POST') {
            expect(formData).toBeInstanceOf(FormData)
          } else {
            expect(formData).not.toBeDefined()
          }
          return Promise.resolve(user)
        },
      )
      vi.setSystemTime(
        new Date(Date.now() + 1000 * 60 * (TOTP_GENERATION_DEFAULTS.period + 1)),
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
      const request = new Request(`${HOST_URL}/verify`, {
        method: 'POST',
        headers: {
          cookie: totpCookie,
        },
        body: formData,
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/verify`)
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.EXPIRED_TOTP)
          expect(params.get('totp')).toBeNull()
        } else throw reason
      })
    })

    test('Should failure redirect on expired totp code with custom error.', async () => {
      const CUSTOM_ERROR = 'TEST: expired totp code'
      const { user, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      const strategy = new TOTPStrategy<typeof user>(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/verify',
          customErrors: {
            expiredTotp: CUSTOM_ERROR,
          },
        },
        async ({ email, formData, request }) => {
          expect(email).toBe(DEFAULT_EMAIL)
          expect(request).toBeInstanceOf(Request)
          if (request.method === 'POST') {
            expect(formData).toBeInstanceOf(FormData)
          } else {
            expect(formData).not.toBeDefined()
          }
          return Promise.resolve(user)
        },
      )
      vi.setSystemTime(
        new Date(Date.now() + 1000 * 60 * (TOTP_GENERATION_DEFAULTS.period + 1)),
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
      const request = new Request(`${HOST_URL}/verify`, {
        method: 'POST',
        headers: {
          cookie: totpCookie,
        },
        body: formData,
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/verify`)
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(CUSTOM_ERROR)
          expect(params.get('totp')).toBeNull()
        } else throw reason
      })
    })

    // test('Should successfully validate magic-link.', async () => {
    //   const { user, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
    //   const strategy = new TOTPStrategy<typeof user>(
    //     {
    //       ...BASE_STRATEGY_OPTIONS,
    //       successRedirect: '/account',
    //       failureRedirect: '/verify',
    //     },
    //     async ({ email, formData, request }) => {
    //       expect(email).toBe(DEFAULT_EMAIL)
    //       expect(request).toBeInstanceOf(Request)
    //       if (request.method === 'POST') {
    //         expect(formData).toBeInstanceOf(FormData)
    //       } else {
    //         expect(formData).not.toBeDefined()
    //       }
    //       return Promise.resolve(user)
    //     },
    //   )
    //   expect(sendTOTPOptions.magicLink).toBeDefined()
    //   invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')
    //   const request = new Request(sendTOTPOptions.magicLink, {
    //     method: 'GET',
    //     headers: {
    //       cookie: totpCookie,
    //     },
    //   })
    //   await strategy.authenticate(request).catch(async (reason) => {
    //     if (reason instanceof Response) {
    //       expect(reason.status).toBe(302)
    //       expect(reason.headers.get('location')).toBe(`/account`)
    //       const setCookieHeader = reason.headers.get('set-cookie') ?? ''
    //       const cookie = new Cookie(setCookieHeader)
    //       const raw = cookie.get('_totp')
    //       expect(raw).toBeDefined()
    //       const params = new URLSearchParams(raw!)
    //       expect(params.get('email')).toBeNull()
    //       expect(params.get('totp')).toBeNull()
    //       expect(params.get('error')).toBeNull()
    //     } else throw reason
    //   })
    // })

    test('Should failure redirect on invalid magic-link code.', async () => {
      const { strategy, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      expect(sendTOTPOptions.magicLink).toBeDefined()
      invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')
      const request = new Request(sendTOTPOptions.magicLink + 'INVALID', {
        method: 'GET',
        headers: {
          cookie: totpCookie,
        },
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/login`)
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.INVALID_TOTP)
        } else throw reason
      })
    })

    test('Should failure redirect on expired magic-link.', async () => {
      const { strategy, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      expect(sendTOTPOptions.magicLink).toBeDefined()
      invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')
      vi.setSystemTime(
        new Date(Date.now() + 1000 * 60 * (TOTP_GENERATION_DEFAULTS.period + 1)),
      )
      const request = new Request(sendTOTPOptions.magicLink, {
        method: 'GET',
        headers: {
          cookie: totpCookie,
        },
      })
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/login`)
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()
          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.EXPIRED_TOTP)
        } else throw reason
      })
    })

    test('Should failure redirect on invalid magic-link path.', async () => {
      const { strategy, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      expect(sendTOTPOptions.magicLink).toBeDefined()
      invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')
      expect(sendTOTPOptions.magicLink).toMatch(MAGIC_LINK_PATH)
      const request = new Request(
        sendTOTPOptions.magicLink.replace(MAGIC_LINK_PATH, '/invalid-magic-link'),
        {
          method: 'GET',
          headers: {
            cookie: totpCookie,
          },
        },
      )
      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/login`)
          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()

          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.INVALID_MAGIC_LINK_PATH)
        } else throw reason
      })
    })

    test('Should failure redirect on missing email.', async () => {
      const { strategy, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      const modifiedCookie = new Cookie(totpCookie)
      const raw = modifiedCookie.get('_totp')
      expect(raw).toBeDefined()

      const params = new URLSearchParams(raw!)
      params.delete('email')
      const newCookie = new SetCookie({
        name: '_totp',
        value: params.toString(),
        httpOnly: true,
        path: '/',
        sameSite: 'Lax',
        secure: true,
      })

      const request = new Request('https://prodserver.com/magic-link?code=KJJERI', {
        method: 'GET',
        headers: {
          cookie: newCookie.toString(),
        },
      })

      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/login`)

          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()

          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.MISSING_SESSION_EMAIL)
        } else throw reason
      })
    })

    test('Should failure redirect on stale magic-link.', async () => {
      let { strategy, sendTOTPOptions, totpCookie } = await setupGenerateSendTOTP()
      const modifiedCookie = new Cookie(totpCookie)
      const raw = modifiedCookie.get('_totp')
      expect(raw).toBeDefined()

      const params = new URLSearchParams(raw!)
      params.delete('totp')
      const newCookie = new SetCookie({
        name: '_totp',
        value: params.toString(),
        httpOnly: true,
        path: '/',
        sameSite: 'Lax',
        secure: true,
      })

      const request = new Request('https://prodserver.com/magic-link?code=KJJERI', {
        method: 'GET',
        headers: {
          cookie: newCookie.toString(),
        },
      })

      await strategy.authenticate(request).catch(async (reason) => {
        if (reason instanceof Response) {
          expect(reason.status).toBe(302)
          expect(reason.headers.get('location')).toBe(`/login`)

          const setCookieHeader = reason.headers.get('set-cookie') ?? ''
          const cookie = new Cookie(setCookieHeader)
          const raw = cookie.get('_totp')
          expect(raw).toBeDefined()

          const params = new URLSearchParams(raw!)
          expect(params.get('error')).toBe(ERRORS.EXPIRED_TOTP)
        } else throw reason
      })
    })

    test('Should failure redirect on magic-link invalid and max TOTP attempts.', async () => {
      let { user, totpCookie, sendTOTPOptions } = await setupGenerateSendTOTP()
      const strategy = new TOTPStrategy<typeof user>(
        {
          ...BASE_STRATEGY_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/verify',
        },
        async ({ email, formData, request }) => {
          expect(email).toBe(DEFAULT_EMAIL)
          expect(request).toBeInstanceOf(Request)
          if (request.method === 'POST') {
            expect(formData).toBeInstanceOf(FormData)
          } else {
            expect(formData).not.toBeDefined()
          }
          return Promise.resolve(user)
        },
      )
      expect(sendTOTPOptions.magicLink).toBeDefined()
      invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')

      for (let i = 0; i <= TOTP_GENERATION_DEFAULTS.maxAttempts; i++) {
        const request = new Request(sendTOTPOptions.magicLink + 'INVALID', {
          method: 'GET',
          headers: {
            cookie: totpCookie,
          },
        })

        await strategy.authenticate(request).catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe(`/verify`)

            const setCookieHeader = reason.headers.get('set-cookie') ?? ''
            totpCookie = setCookieHeader
            const cookie = new Cookie(setCookieHeader)
            const raw = cookie.get('_totp')
            expect(raw).toBeDefined()

            const params = new URLSearchParams(raw!)
            expect(params.get('error')).toBe(
              i < TOTP_GENERATION_DEFAULTS.maxAttempts
                ? ERRORS.INVALID_TOTP
                : ERRORS.EXPIRED_TOTP,
            )

            if (i >= TOTP_GENERATION_DEFAULTS.maxAttempts) {
              expect(params.get('totp')).toBeNull()
            }
          } else throw reason
        })
      }
    })
  })
})

describe('[ Utils ]', () => {
  test('Should use the origin from the request for the magic-link.', async () => {
    const samples: Array<[string, string]> = [
      ['http://localhost/login', 'http://localhost/magic-link?code=U2N2EY'],
      ['http://localhost:3000/login', 'http://localhost:3000/magic-link?code=U2N2EY'],
      ['http://127.0.0.1/login', 'http://127.0.0.1/magic-link?code=U2N2EY'],
      ['http://127.0.0.1:3000/login', 'http://127.0.0.1:3000/magic-link?code=U2N2EY'],
      ['http://localhost:8788/signin', 'http://localhost:8788/magic-link?code=U2N2EY'],
      ['https://host.com/login', 'https://host.com/magic-link?code=U2N2EY'],
      ['https://host.com:3000/login', 'https://host.com:3000/magic-link?code=U2N2EY'],
    ]

    for (const [requestUrl, magicLinkUrl] of samples) {
      const request = new Request(requestUrl)
      expect(
        generateMagicLink({
          magicLinkPath: '/magic-link',
          param: 'code',
          code: 'U2N2EY',
          request,
        }),
      ).toBe(magicLinkUrl)
    }
  })

  test('Should throw an error on invalid secret.', async () => {
    const secrets = [
      'b2FE35059924CDBF5B52A84765B8B010F5291993A9BC39410139D4F5110060',
      'b2FE35059924CDBF5B52A84765B8B010F5291993A9BC39410139D4F511006034a',
      'b2FE35059924CDBF5B52A84765B8B010F5291993A9BC39410139D4F51100603#',
    ]

    for (const secret of secrets) {
      expect(() => asJweKey(secret)).toThrow()
    }
  })
})
