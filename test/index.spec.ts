import type { Session } from '@remix-run/server-runtime'
import type {
  SendTOTPOptions,
  TOTPDataDeprecated,
  TOTPStrategyOptions,
} from '../src/index'

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import invariant from 'tiny-invariant'

import { TOTPStrategy } from '../src/index'
import { generateMagicLink } from '../src/utils'
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

const TOTP_STRATEGY_OPTIONS: TOTPStrategyOptions = {
  secret: SECRET_ENV,
  createTOTP,
  readTOTP,
  updateTOTP,
  sendTOTP,
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
    const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
    expect(strategy.name).toBe(STRATEGY_NAME)
  })

  test('Should throw an Error on missing required secret option.', async () => {
    const strategy = new TOTPStrategy(
      // @ts-expect-error - Error is expected since missing secret option.
      { createTOTP, readTOTP, updateTOTP, sendTOTP },
      verify,
    )
    const request = new Request(`${HOST_URL}/login`, {
      method: 'POST',
    })
    await expect(() =>
      strategy.authenticate(request, sessionStorage, { ...AUTH_OPTIONS }),
    ).rejects.toThrow(ERRORS.REQUIRED_ENV_SECRET)
  })

  test('Should throw an Error on missing required successRedirect option.', async () => {
    const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
    const request = new Request(`${HOST_URL}/login`, {
      method: 'POST',
    })
    await expect(() =>
      strategy.authenticate(request, sessionStorage, { ...AUTH_OPTIONS }),
    ).rejects.toThrow(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)
  })

  test('Should throw an Error on missing required failureRedirect option.', async () => {
    const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
    const request = new Request(`${HOST_URL}/login`, {
      method: 'POST',
    })
    await expect(() =>
      strategy.authenticate(request, sessionStorage, {
        ...AUTH_OPTIONS,
        successRedirect: '/verify',
      }),
    ).rejects.toThrow(ERRORS.REQUIRED_FAILURE_REDIRECT_URL)
  })
})

describe('[ TOTP ]', () => {
  describe('Generate/Send TOTP', () => {
    test('Should failure redirect on invalid email.', async () => {
      const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, '@invalid-email')
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe('/login')
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(AUTH_OPTIONS.sessionErrorKey)).toEqual({
              message: ERRORS.INVALID_EMAIL,
            })
          } else throw reason
        })
    })

    test('Should generate/send TOTP for form email.', async () => {
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
      })
      const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
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
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe('/verify')
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(SESSION_KEYS.EMAIL)).toBe(DEFAULT_EMAIL)
            expect(session.get(SESSION_KEYS.TOTP)).toBeDefined()
          } else throw reason
        })

      expect(sendTOTP).toHaveBeenCalledTimes(1)
    })

    test('Should generate/send TOTP for form email ignoring form totp code.', async () => {
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
      })
      const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      formData.append(FORM_FIELDS.TOTP, '123456')
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toMatch('/verify')
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(SESSION_KEYS.EMAIL)).toBe(DEFAULT_EMAIL)
            expect(session.get(SESSION_KEYS.TOTP)).toBeDefined()
          } else throw reason
        })

      expect(sendTOTP).toHaveBeenCalledTimes(1)
    })

    test('Should generate/send TOTP for form email ignoring session email.', async () => {
      let session: Session | undefined
      let sessionTotp: unknown
      const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
      const formDataToPopulateSessionEmail = new FormData()
      formDataToPopulateSessionEmail.append(FORM_FIELDS.EMAIL, 'email@session.com')
      const requestToPopulateSessionEmail = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formDataToPopulateSessionEmail,
      })
      await strategy
        .authenticate(requestToPopulateSessionEmail, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe('/verify')
            session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(SESSION_KEYS.EMAIL)).toBe('email@session.com')
            expect(session.get(SESSION_KEYS.TOTP)).toBeDefined()
            sessionTotp = session.get(SESSION_KEYS.TOTP)
          } else throw reason
        })
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
      })
      if (!session) throw new Error('Undefined session.')
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      const request = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      })
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe('/verify')
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(SESSION_KEYS.EMAIL)).toBe(DEFAULT_EMAIL)
            expect(session.get(SESSION_KEYS.TOTP)).toBeDefined()
            expect(session.get(SESSION_KEYS.TOTP)).not.toEqual(sessionTotp)
          } else throw reason
        })
      expect(sendTOTP).toHaveBeenCalledTimes(2)
    })

    test('Should generate/send TOTP for empty form data with session email.', async () => {
      sendTOTP.mockImplementation(async (options: SendTOTPOptions) => {
        expect(options.email).toBe(DEFAULT_EMAIL)
        expect(options.code).to.not.equal('')
      })
      let session: Session | undefined
      let sessionTotp: unknown
      const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL)
      const requestToPopulateSessionEmail = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        body: formData,
      })
      await strategy
        .authenticate(requestToPopulateSessionEmail, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe('/verify')
            session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(SESSION_KEYS.EMAIL)).toBe(DEFAULT_EMAIL)
            expect(session.get(SESSION_KEYS.TOTP)).toBeDefined()
            sessionTotp = session.get(SESSION_KEYS.TOTP)
          } else throw reason
        })
      if (!session) throw new Error('Undefined session.')
      const emptyFormRequest = new Request(`${HOST_URL}/login`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: new FormData(),
      })
      await strategy
        .authenticate(emptyFormRequest, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/verify',
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe('/verify')
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(SESSION_KEYS.EMAIL)).toBe(DEFAULT_EMAIL)
            expect(session.get(SESSION_KEYS.TOTP)).toBeDefined()
            expect(session.get(SESSION_KEYS.TOTP)).not.toEqual(sessionTotp)
          } else throw reason
        })
      expect(sendTOTP).toHaveBeenCalledTimes(2)
    })
  })

  describe('Validate TOTP', () => {
    async function setupGenerateSendTOTP(
      totpStrategyOptions: Partial<TOTPStrategyOptions> = {},
    ) {
      const user = { name: 'Joe Schmoe' }
      let sendTOTPOptions: SendTOTPOptions | undefined
      let session: Session | undefined

      const strategy = new TOTPStrategy<typeof user>(
        {
          secret: SECRET_ENV,
          createTOTP,
          readTOTP,
          updateTOTP,
          sendTOTP: async (options) => {
            sendTOTPOptions = options
            expect(options.email).toBe(DEFAULT_EMAIL)
            expect(options.magicLink).toBe(`${HOST_URL}/magic-link?code=${options.code}`)
          },
          ...totpStrategyOptions,
        },
        () => {
          return Promise.resolve(user)
        },
      )
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
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe('/verify')
            session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
          } else throw reason
        })

      expect(sendTOTPOptions).toBeDefined()
      invariant(sendTOTPOptions, 'Undefined sendTOTPOptions')
      expect(session).toBeDefined()
      invariant(session, 'Undefined session')
      return { strategy, sendTOTPOptions, session, user }
    }

    test('Should successfully validate magic-link', async () => {
      const { strategy, sendTOTPOptions, session } = await setupGenerateSendTOTP()
      expect(sendTOTPOptions.magicLink).toBeDefined()
      invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')
      const request = new Request(sendTOTPOptions.magicLink, {
        method: 'GET',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
      })
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/login',
        })
        .catch((reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe(`/account`)
          } else throw reason
        })
    })

    test('Should failure redirect on invalid magic-link code.', async () => {
      const { strategy, sendTOTPOptions, session } = await setupGenerateSendTOTP()
      expect(sendTOTPOptions.magicLink).toBeDefined()
      invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')
      const request = new Request(sendTOTPOptions.magicLink + 'INVALID', {
        method: 'GET',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
      })
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe(`/login`)
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(AUTH_OPTIONS.sessionErrorKey)).toEqual({
              message: ERRORS.INVALID_TOTP,
            })
          } else throw reason
        })
    })

    test('Should successfully validate totp code', async () => {
      const { strategy, sendTOTPOptions, session, user } = await setupGenerateSendTOTP()
      const formData = new FormData()
      formData.append(FORM_FIELDS.TOTP, sendTOTPOptions.code)
      const request = new Request(`${HOST_URL}/verify`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      })
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/login',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe(`/account`)
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get('user')).toEqual(user)
          } else throw reason
        })
    })

    test('Should failure redirect on invalid totp code', async () => {
      const { strategy, sendTOTPOptions, session } = await setupGenerateSendTOTP()
      const formData = new FormData()
      formData.append(FORM_FIELDS.TOTP, sendTOTPOptions.code + 'INVALID')
      const request = new Request(`${HOST_URL}/verify`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      })
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/account',
          failureRedirect: '/verify',
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe(`/verify`)
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.get(AUTH_OPTIONS.sessionErrorKey)).toEqual({
              message: ERRORS.INVALID_TOTP,
            })
          } else throw reason
        })
    })

    test.only('Should failure redirect on invalid and max TOTP attempts.', async () => {
      let { strategy, session, sendTOTPOptions } = await setupGenerateSendTOTP()
      for (let i = 0; i <= TOTP_GENERATION_DEFAULTS.maxAttempts; i++) {
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, sendTOTPOptions.code + 'INVALID')
        const request = new Request(`${HOST_URL}/verify`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session),
          },
          body: formData,
        })
        await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/account',
            failureRedirect: '/verify',
          })
          .catch(async (reason) => {
            if (reason instanceof Response) {
              expect(reason.status).toBe(302)
              expect(reason.headers.get('location')).toBe(`/verify`)
              session = await sessionStorage.getSession(
                reason.headers.get('set-cookie') ?? '',
              )
              expect(session.get(AUTH_OPTIONS.sessionErrorKey)).toEqual({
                message: i < TOTP_GENERATION_DEFAULTS.maxAttempts ? ERRORS.INVALID_TOTP : ERRORS.EXPIRED_TOTP,
              })
            } else throw reason
          })
      }
    })

    async function setupFirstAuthPhase(
      totpStrategyOptions: Partial<TOTPStrategyOptions> = {},
    ) {
      const user = { name: 'Joe Schmoe' }
      let totpData: TOTPDataDeprecated | undefined
      let totpDataExpiresAt: Date | undefined
      let sendTOTPOptions: SendTOTPOptions | undefined
      let session: Session | undefined
      const strategy = new TOTPStrategy<typeof user>(
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
            invariant(totpData, 'Undefined totpData')
            expect(totpData.hash).toBe(hash)
            return totpData
          },
          updateTOTP: async (hash, data, expiresAt) => {
            expect(totpData).toBeDefined()
            invariant(totpData, 'Undefined totpData')
            expect(totpData.hash).toBe(hash)
            expect(totpDataExpiresAt).toEqual(expiresAt)
            totpData = { ...totpData, ...data }
          },
          sendTOTP: async (options) => {
            sendTOTPOptions = options
            expect(options.email).toBe(DEFAULT_EMAIL)
            expect(options.magicLink).toBe(`${HOST_URL}/magic-link?code=${options.code}`)
          },
          ...totpStrategyOptions,
        },
        () => {
          return Promise.resolve(user)
        },
      )
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
            expect(reason.headers.get('location')).toBe('/verify')
            session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
          } else throw reason
        })

      expect(totpData).toBeDefined()
      invariant(totpData, 'Undefined totpData')
      expect(totpData.active).toBeTruthy()
      expect(totpDataExpiresAt).toBeDefined()
      invariant(totpDataExpiresAt, 'Undefined totpDataExpiresAt')
      expect(sendTOTPOptions).toBeDefined()
      invariant(sendTOTPOptions, 'Undefined sendTOTPOptions')
      expect(session).toBeDefined()
      invariant(session, 'Undefined session')
      return { strategy, totpData, totpDataExpiresAt, sendTOTPOptions, session, user }
    }

    test('Should throw an Error on invalid and max TOTP attempts.', async () => {
      const { strategy, session, sendTOTPOptions } = await setupFirstAuthPhase()
      for (let i = 0; i < TOTP_GENERATION_DEFAULTS.maxAttempts + 1; i++) {
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, sendTOTPOptions.code + i)
        const request = new Request(`${HOST_URL}/verify`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session),
          },
          body: formData,
        })
        await expect(() =>
          strategy.authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/',
          }),
        ).rejects.toThrowError(
          i < TOTP_GENERATION_DEFAULTS.maxAttempts
            ? ERRORS.INVALID_TOTP
            : ERRORS.INACTIVE_TOTP,
        )
      }
    })

    test('Should throw an Error on expired TOTP verification.', async () => {
      const { strategy, session, sendTOTPOptions } = await setupFirstAuthPhase()
      vi.setSystemTime(
        new Date(Date.now() + 1000 * 60 * (TOTP_GENERATION_DEFAULTS.period + 1)),
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.TOTP, sendTOTPOptions.code)
      const request = new Request(`${HOST_URL}/verify`, {
        method: 'POST',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      })
      await expect(() =>
        strategy.authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        }),
      ).rejects.toThrow(ERRORS.INACTIVE_TOTP)
    })

    test('Should throw an Error on expired magic-link TOTP verification.', async () => {
      const { strategy, session, sendTOTPOptions } = await setupFirstAuthPhase()
      expect(sendTOTPOptions.magicLink).toBeDefined()
      invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')
      vi.setSystemTime(
        new Date(Date.now() + 1000 * 60 * (TOTP_GENERATION_DEFAULTS.period + 1)),
      )
      const request = new Request(sendTOTPOptions.magicLink, {
        method: 'GET',
        headers: {
          cookie: await sessionStorage.commitSession(session),
        },
      })
      await expect(() =>
        strategy.authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/account',
        }),
      ).rejects.toThrow(ERRORS.INACTIVE_TOTP)
    })

    test('Should throw an Error on invalid magic-link path.', async () => {
      const { strategy, sendTOTPOptions } = await setupFirstAuthPhase()
      expect(sendTOTPOptions.magicLink).toBeDefined()
      invariant(sendTOTPOptions.magicLink, 'Magic link is undefined.')
      expect(sendTOTPOptions.magicLink).toMatch(/\/magic-link/)
      const request = new Request(
        sendTOTPOptions.magicLink.replace(/\/magic-link/, '/invalid-magic-link'),
        { method: 'GET' },
      )
      await expect(() =>
        strategy.authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/account',
        }),
      ).rejects.toThrow(ERRORS.INVALID_MAGIC_LINK_PATH)
    })
  })

  describe.skip('End to End', () => {
    test('Should authenticate user with valid TOTP.', async () => {
      const user = { name: 'Joe Schmoe' }
      let totpData: TOTPDataDeprecated | undefined
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
            invariant(totpData, 'TOTP data is undefined.')
            expect(totpData.hash).toBe(hash)
            return totpData
          },
          updateTOTP: async (hash, data, expiresAt) => {
            expect(totpData).toBeDefined()
            invariant(totpData, 'TOTP data is undefined.')
            expect(totpData.hash).toBe(hash)
            expect(totpDataExpiresAt).toEqual(expiresAt)
            totpData = { ...totpData, ...data }
          },
          sendTOTP: async (options) => {
            sendTOTPOptions = options
            expect(options.email).toBe(DEFAULT_EMAIL)
            expect(options.magicLink).toBe(`${HOST_URL}/magic-link?code=${options.code}`)
          },
        },
        () => {
          return Promise.resolve(user)
        },
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
            successRedirect: '/verify',
          })
          .catch(async (reason) => {
            if (reason instanceof Response) {
              expect(reason.status).toBe(302)
              expect(reason.headers.get('location')).toBe('/verify')
              session = await sessionStorage.getSession(
                reason.headers.get('set-cookie') ?? '',
              )
            } else throw reason
          })
      }
      expect(totpData).toBeDefined()
      invariant(totpData, 'Undefined totpData')
      expect(totpData.active).toBeTruthy()
      expect(totpData.attempts).toBe(0)
      expect(totpDataExpiresAt).toBeDefined()
      invariant(totpDataExpiresAt, 'Undefined totpDataExpiresAt')
      expect(sendTOTPOptions).toBeDefined()
      invariant(sendTOTPOptions, 'Undefined sendTOTPOptions')
      expect(session).toBeDefined()
      invariant(session, 'Undefined session')
      expect(session.get(SESSION_KEYS.EMAIL)).toBe(DEFAULT_EMAIL)
      expect(session.get(SESSION_KEYS.TOTP)).toBe(totpData?.hash)
      expect(session.get(SESSION_KEYS.TOTP_EXPIRES_AT)).toBe(
        totpDataExpiresAt?.toISOString(),
      )
      {
        const formData = new FormData()
        formData.append(FORM_FIELDS.TOTP, sendTOTPOptions.code)

        const request = new Request(`${HOST_URL}`, {
          method: 'POST',
          headers: {
            cookie: await sessionStorage.commitSession(session),
          },
          body: formData,
        })

        await strategy
          .authenticate(request, sessionStorage, {
            ...AUTH_OPTIONS,
            successRedirect: '/account',
          })
          .catch(async (reason) => {
            if (reason instanceof Response) {
              expect(reason.status).toBe(302)
              expect(reason.headers.get('location')).toBe('/account')
              session = await sessionStorage.getSession(
                reason.headers.get('set-cookie') ?? '',
              )
            } else throw reason
          })
      }
      expect(totpData).toBeDefined()
      expect(totpData.active).toBeFalsy()
      expect(totpData.attempts).toBe(0)
      expect(session).toBeDefined()
      invariant(session, 'Undefined session')
      expect(session.get('user')).toEqual(user)
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
