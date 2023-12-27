import type { Session } from '@remix-run/server-runtime'
import type { SendTOTPOptions, TOTPData } from '../src/index'

import { describe, test, expect, afterEach, vi, beforeEach } from 'vitest'
import { AuthorizationError } from 'remix-auth'

import { TOTPStrategy } from '../src/index'
import { generateTOTP, generateMagicLink, signJWT } from '../src/utils'
import { STRATEGY_NAME, FORM_FIELDS, SESSION_KEYS, ERRORS } from '../src/constants'

import {
  SECRET_ENV,
  HOST_URL,
  AUTH_OPTIONS,
  TOTP_GENERATION_DEFAULTS,
  MAGIC_LINK_GENERATION_DEFAULTS,
  DEFAULT_EMAIL,
  sessionStorage,
} from './utils'

/**
 * Mocks.
 */
export const verify = vi.fn()
export const createTOTP = vi.fn()
export const readTOTP = vi.fn()
export const updateTOTP = vi.fn()
export const sendTOTP = vi.fn()
export const validateEmail = vi.fn()

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
        secret: SECRET_ENV,
        createTOTP,
        readTOTP,
        updateTOTP,
        sendTOTP,
      },
      verify,
    )

    expect(strategy.name).toBe(STRATEGY_NAME)
  })

  test('Should throw an Error on missing required secret option.', async () => {
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
    })

    const strategy = new TOTPStrategy(
      // @ts-expect-error - Error is expected since missing secret option.
      { createTOTP, readTOTP, updateTOTP, sendTOTP },
      verify,
    )

    await expect(() =>
      strategy.authenticate(request, sessionStorage, { ...AUTH_OPTIONS }),
    ).rejects.toThrow(ERRORS.REQUIRED_ENV_SECRET)
  })

  test('Should throw an Error on missing required successRedirect option.', async () => {
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
    })

    const strategy = new TOTPStrategy(
      {
        secret: SECRET_ENV,
        createTOTP,
        readTOTP,
        updateTOTP,
        sendTOTP,
      },
      verify,
    )

    await expect(() =>
      strategy.authenticate(request, sessionStorage, { ...AUTH_OPTIONS }),
    ).rejects.toThrow(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)
  })

  test('Should throw a custom Error message.', async () => {
    const CUSTOM_ERROR = 'Custom error message.'

    const formData = new FormData()
    formData.append(FORM_FIELDS.EMAIL, '')

    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      body: formData,
    })

    const strategy = new TOTPStrategy(
      {
        secret: SECRET_ENV,
        createTOTP,
        readTOTP,
        updateTOTP,
        sendTOTP,
        customErrors: {
          requiredEmail: CUSTOM_ERROR,
        },
      },
      verify,
    )

    await expect(() =>
      strategy.authenticate(request, sessionStorage, {
        ...AUTH_OPTIONS,
        successRedirect: '/',
      }),
    ).rejects.toThrow(CUSTOM_ERROR)
  })
})

describe('[ TOTP ]', () => {
  describe('1st Authentication Phase', () => {
    test('Should throw an Error on missing formData email.', async () => {
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, '')

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )

      await expect(() =>
        strategy.authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        }),
      ).rejects.toThrow(ERRORS.REQUIRED_EMAIL)
    })

    test('Should throw an Error on invalid form email.', async () => {
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, '@invalid-email')

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )

      await expect(() =>
        strategy.authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        }),
      ).rejects.toThrow(ERRORS.INVALID_EMAIL)
    })

    test('Should call createTOTP function.', async () => {
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)

      expect(createTOTP).toHaveBeenCalledTimes(1)
    })

    test('Should call sendTOTP function.', async () => {
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)

      expect(sendTOTP).toHaveBeenCalledTimes(1)
    })

    test('Should contain auth:email, auth:totp, and auth:totpExpiresAt properties in session.', async () => {
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      const session = await sessionStorage.getSession(
        result.headers.get('set-cookie') ?? '',
      )

      expect(session.data).toHaveProperty(SESSION_KEYS.EMAIL)
      expect(session.data).toHaveProperty(SESSION_KEYS.TOTP)
      expect(session.data).toHaveProperty(SESSION_KEYS.TOTP_EXPIRES_AT)
    })

    test('Should contain Location header pointing to provided successRedirect url.', async () => {
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/verify',
        })
        .catch((error) => error)) as Response

      expect(result.headers.get('location')).toMatch('/verify')
    })

    test('Re-send TOTP - Should invalidate previous TOTP.', async () => {
      const session = await sessionStorage.getSession()
      session.set(SESSION_KEYS.EMAIL, DEFAULT_EMAIL)
      session.set(SESSION_KEYS.TOTP, 'JWT-SIGNED')
      session.set(
        SESSION_KEYS.TOTP_EXPIRES_AT,
        new Date(Date.now() + TOTP_GENERATION_DEFAULTS.period * 1000).toISOString(),
      )

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: new FormData(), // Empty form data indicates re-send new TOTP
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
          validateEmail,
        },
        verify,
      )
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)

      expect(updateTOTP).toHaveBeenCalledTimes(1)
      expect(validateEmail).toHaveBeenCalledTimes(1)
    })
  })

  describe('2nd Authentication Phase', () => {
    test('Should invalidate current TOTP.', async () => {
      let totpData: TOTPData | undefined
      let session: Session | undefined
      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP: async (data) => {
            expect(totpData).not.toBeDefined()
            totpData = data
          },
          readTOTP: async (hash) => {
            expect(totpData).toBeDefined()
            expect(totpData?.hash).toBe(hash)
            return totpData!
          },
          updateTOTP: async (hash, data) => {
            expect(totpData).toBeDefined()
            expect(totpData?.hash).toBe(hash)
            totpData = { ...totpData!, ...data }
          },
          sendTOTP,
        },
        verify,
      )
      {
        const formData = new FormData()
        formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          body: formData,
        })
        await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          })
          .catch(async (reason) => {
            if (reason instanceof Response) {
              expect(reason.status).toBe(302)
              session = await sessionStorage.getSession(
                reason.headers.get('set-cookie') ?? '',
              )
            } else throw reason
          })
      }
      expect(totpData).toBeDefined()
      expect(totpData?.active).toBeTruthy()
      expect(session).toBeDefined()

      for (let i = 0; i < TOTP_GENERATION_DEFAULTS.maxAttempts; i++) {
        const { otp } = generateTOTP(TOTP_GENERATION_DEFAULTS)
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, otp)
        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session!),
          },
          body: formData,
        })
        await expect(() =>
          strategy.authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          }),
        ).rejects.toThrowError(ERRORS.INVALID_TOTP)
      }
      expect(totpData).toBeDefined()
      expect(totpData?.active).toBeTruthy()
      {
        const { otp } = generateTOTP(TOTP_GENERATION_DEFAULTS)
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, otp)
        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session!),
          },
          body: formData,
        })
        await expect(() =>
          strategy.authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          }),
        ).rejects.toThrowError(ERRORS.INACTIVE_TOTP)
      }
      expect(totpData).toBeDefined()
      expect(totpData?.active).toBeFalsy()
    })

    test('Should throw an Error on missing TOTP from database.', async () => {
      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      let session: Session | undefined
      {
        const formData = new FormData()
        formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          body: formData,
        })
        await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          })
          .catch(async (reason) => {
            if (reason instanceof Response) {
              expect(reason.status).toBe(302)
              session = await sessionStorage.getSession(
                reason.headers.get('set-cookie') ?? '',
              )
            } else throw reason
          })
      }
      {
        const totp = generateTOTP(TOTP_GENERATION_DEFAULTS)
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, totp.otp)

        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session!),
          },
          body: formData,
        })
        await expect(() =>
          strategy.authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          }),
        ).rejects.toThrowError(ERRORS.TOTP_NOT_FOUND)
      }
    })

    test('Should throw a custom Error message on missing TOTP from database.', async () => {
      const CUSTOM_ERROR = 'Custom error message.'
      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
          customErrors: {
            totpNotFound: CUSTOM_ERROR,
          },
        },
        verify,
      )
      let session: Session | undefined
      {
        const formData = new FormData()
        formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          body: formData,
        })
        await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          })
          .catch(async (reason) => {
            if (reason instanceof Response) {
              expect(reason.status).toBe(302)
              session = await sessionStorage.getSession(
                reason.headers.get('set-cookie') ?? '',
              )
            } else throw reason
          })
      }
      {
        const totp = generateTOTP(TOTP_GENERATION_DEFAULTS)
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, totp.otp)

        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session!),
          },
          body: formData,
        })
        await expect(() =>
          strategy.authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          }),
        ).rejects.toThrowError(CUSTOM_ERROR)
      }
    })

    test('Should throw an Error on inactive TOTP.', async () => {
      readTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: false }),
      )

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS)
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      })

      const formData = new FormData()
      formData.append(FORM_FIELDS.TOTP, _otp)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      expect(result).toEqual(new AuthorizationError(ERRORS.INACTIVE_TOTP))
    })

    test('Should throw an Error on max TOTP attempts.', async () => {
      readTOTP.mockImplementation(() =>
        Promise.resolve({
          hash: signedTotp,
          attempts: TOTP_GENERATION_DEFAULTS.maxAttempts,
          active: true,
        }),
      )

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS)
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      })

      const formData = new FormData()
      formData.append(FORM_FIELDS.TOTP, _otp)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      expect(result).toEqual(new AuthorizationError(ERRORS.INACTIVE_TOTP))
    })

    test('Should throw an Error on invalid (expired) JWT.', async () => {
      readTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: true }),
      )

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS)
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: 0,
        secretKey: SECRET_ENV,
      })

      const formData = new FormData()
      formData.append(FORM_FIELDS.TOTP, _otp)

      const session = await sessionStorage.getSession()
      session.set(SESSION_KEYS.TOTP, signedTotp)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      expect(result).toEqual(new AuthorizationError(ERRORS.INACTIVE_TOTP))
    })

    test('Should throw an Error on invalid (expired) TOTP verification.', async () => {
      let totpData: TOTPData | undefined
      let sendTOTPOptions: SendTOTPOptions | undefined
      let session: Session | undefined
      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP: async (data) => {
            expect(totpData).not.toBeDefined()
            totpData = data
          },
          readTOTP: async (hash) => {
            expect(totpData).toBeDefined()
            expect(totpData?.hash).toBe(hash)
            return totpData!
          },
          updateTOTP,
          sendTOTP: async (options) => {
            sendTOTPOptions = options
          },
        },
        verify,
      )
      {
        const formData = new FormData()
        formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
        const request = new Request(`${HOST_URL}/login`, {
          method: 'POST',
          body: formData,
        })

        await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/verify',
          })
          .catch(async (reason) => {
            if (reason instanceof Response) {
              expect(reason.status).toBe(302)
              session = await sessionStorage.getSession(
                reason.headers.get('set-cookie') ?? '',
              )
            } else throw reason
          })
      }
      expect(totpData).toBeDefined()
      expect(totpData?.active).toBeTruthy()
      expect(sendTOTPOptions).toBeDefined()
      expect(session).toBeDefined()
      vi.setSystemTime(
        new Date(Date.now() + 1000 * 60 * (TOTP_GENERATION_DEFAULTS.period + 1)),
      )
      {
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, sendTOTPOptions!.code)
        const request = new Request(`${HOST_URL}/verify`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session!),
          },
          body: formData,
        })
        await expect(() =>
          strategy.authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          }),
        ).rejects.toThrow(ERRORS.INACTIVE_TOTP)
      }
    })

    test.only('Should throw an Error on invalid (expired) magic-link TOTP verification.', async () => {
      let totpData: TOTPData | undefined
      let sendTOTPOptions: SendTOTPOptions | undefined
      let session: Session | undefined
      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP: async (data) => {
            expect(totpData).not.toBeDefined()
            totpData = data
          },
          readTOTP: async (hash) => {
            expect(totpData).toBeDefined()
            expect(totpData?.hash).toBe(hash)
            return totpData!
          },
          updateTOTP,
          sendTOTP: async (options) => {
            sendTOTPOptions = options
          },
        },
        verify,
      )
      {
        const formData = new FormData()
        formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
        const request = new Request(`${HOST_URL}/login`, {
          method: 'POST',
          body: formData,
        })
        await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/verify',
          })
          .catch(async (reason) => {
            if (reason instanceof Response) {
              expect(reason.status).toBe(302)
              session = await sessionStorage.getSession(
                reason.headers.get('set-cookie') ?? '',
              )
            } else throw reason
          })
      }
      expect(totpData).toBeDefined()
      expect(totpData?.active).toBeTruthy()
      expect(sendTOTPOptions).toBeDefined()
      expect(sendTOTPOptions?.magicLink).toBeDefined()
      expect(session).toBeDefined()
      vi.setSystemTime(
        new Date(Date.now() + 1000 * 60 * (TOTP_GENERATION_DEFAULTS.period + 1)),
      )
      {
        const request = new Request(sendTOTPOptions!.magicLink!, {
          method: 'GET',
          headers: {
            cookie: await sessionStorage.commitSession(session!),
          },
        })
        await expect(() =>
          strategy.authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/account',
          }),
        ).rejects.toThrow(ERRORS.INACTIVE_TOTP)
      }
    })

    test('Should throw an Error on invalid magic-link callback path.', async () => {
      const { otp: _otp } = generateTOTP(TOTP_GENERATION_DEFAULTS)

      const magicLink = generateMagicLink({
        ...MAGIC_LINK_GENERATION_DEFAULTS,
        callbackPath: '/invalid',
        param: 'code',
        code: _otp,
        request: new Request(HOST_URL),
      })

      const request = new Request(`${magicLink}`, {
        method: 'GET',
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      expect(result).toEqual(new AuthorizationError(ERRORS.INVALID_MAGIC_LINK_PATH))
    })

    test('Should successfully validate TOTP.', async () => {
      readTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: true }),
      )

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS)
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      })

      const formData = new FormData()
      formData.append(FORM_FIELDS.TOTP, _otp)

      const session = await sessionStorage.getSession()
      session.set(SESSION_KEYS.TOTP, signedTotp)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      expect(result.status).toBe(302)
      expect(result.headers.get('location')).toMatch('/')
    })

    test('Should contain user property in session.', async () => {
      readTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: true }),
      )
      verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }))

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS)
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      })

      const formData = new FormData()
      formData.append(FORM_FIELDS.TOTP, _otp)

      let session = await sessionStorage.getSession()
      session.set(SESSION_KEYS.TOTP, signedTotp)

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      })

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP,
        },
        verify,
      )
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response

      session = await sessionStorage.getSession(result.headers.get('set-cookie') ?? '')

      expect(session.data).toHaveProperty('user')
      expect(session.data.user.name).toBe('John Doe')
    })
  })

  describe('End to End', () => {
    test('Should authenticate user with valid TOTP.', async () => {
      let totpData: TOTPData | undefined
      let totpDataExpiresAt: Date | undefined
      let sendTOTPOptions: SendTOTPOptions | undefined
      let session: Session | undefined

      const strategy = new TOTPStrategy(
        {
          secret: SECRET_ENV,
          createTOTP: async (data, expiresAt) => {
            expect(totpData).not.toBeDefined()
            expect(data.active).toBeTruthy()
            expect(data.attempts).toBe(0)
            totpData = data
            totpDataExpiresAt = expiresAt
          },
          readTOTP: async (hash) => {
            expect(totpData).toBeDefined()
            expect(totpData?.hash).toBe(hash)
            return totpData!
          },
          updateTOTP: async (hash, data, expiresAt) => {
            expect(totpData).toBeDefined()
            expect(totpData?.hash).toBe(hash)
            expect(totpDataExpiresAt).toEqual(expiresAt)
            totpData = { ...totpData!, ...data }
          },
          sendTOTP: async (options) => {
            sendTOTPOptions = options
            expect(options.email).toBe(DEFAULT_EMAIL)
            expect(options.magicLink).toBe(`${HOST_URL}/magic-link?code=${options.code}`)
          },
        },
        verify,
      )
      {
        const formData = new FormData()
        formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          body: formData,
        })

        const result = await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/verify',
          })
          .catch((reason) => {
            if (reason instanceof Response) {
              return reason
            }
            throw reason
          })
        expect(result).toBeInstanceOf(Response)
        if (result instanceof Response) {
          expect(result.status).toBe(302)
          expect(result.headers.get('location')).toBe('/verify')
          session = await sessionStorage.getSession(
            result.headers.get('set-cookie') ?? '',
          )
          expect(totpData).toBeDefined()
          expect(totpData!.active).toBeTruthy()
          expect(totpData!.attempts).toBe(0)
          expect(totpDataExpiresAt).toBeDefined()
          expect(session.get(SESSION_KEYS.EMAIL)).toBe(DEFAULT_EMAIL)
          expect(session.get(SESSION_KEYS.TOTP)).toBe(totpData?.hash)
          expect(session.get(SESSION_KEYS.TOTP_EXPIRES_AT)).toBe(
            totpDataExpiresAt?.toISOString(),
          )
        }
      }
      {
        expect(totpData).toBeDefined()
        expect(sendTOTPOptions).toBeDefined()
        expect(session).toBeDefined()
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, sendTOTPOptions!.code)
        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session!),
          },
          body: formData,
        })

        const result = await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          })
          .catch((reason) => {
            if (reason instanceof Response) {
              return reason
            }
            throw reason
          })
        expect(result).toBeInstanceOf(Response)
        if (result instanceof Response) {
          expect(result.status).toBe(302)
          expect(result.headers.get('location')).toBe(`/`)
          expect(totpData).toBeDefined()
          expect(totpData!.active).toBeFalsy()
          expect(totpData!.attempts).toBe(0)
        }
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
          ...MAGIC_LINK_GENERATION_DEFAULTS,
          param: 'code',
          code: 'U2N2EY',
          request,
        }),
      ).toBe(magicLinkUrl)
    }
  })
})
