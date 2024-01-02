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
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
    })
    await expect(() =>
      strategy.authenticate(request, sessionStorage, { ...AUTH_OPTIONS }),
    ).rejects.toThrow(ERRORS.REQUIRED_ENV_SECRET)
  })

  test('Should throw an Error on missing required successRedirect option.', async () => {
    const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
    })
    await expect(() =>
      strategy.authenticate(request, sessionStorage, { ...AUTH_OPTIONS }),
    ).rejects.toThrow(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL)
  })

  test.skip('Should throw a custom Error message.', async () => {
    const CUSTOM_ERROR = 'Custom error message.'
    const strategy = new TOTPStrategy(
      {
        ...TOTP_STRATEGY_OPTIONS,
        customErrors: {
          requiredEmail: CUSTOM_ERROR,
        },
      },
      verify,
    )
    const formData = new FormData()
    formData.append(FORM_FIELDS.EMAIL, '')
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      body: formData,
    })
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
    test.skip('Should throw an Error on missing formData email.', async () => {
      const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, '')
      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })
      await expect(() =>
        strategy.authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        }),
      ).rejects.toThrow(ERRORS.REQUIRED_EMAIL)
    })

    test('Should throw an Error on invalid form email.', async () => {
      const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
      const formData = new FormData()
      formData.append(FORM_FIELDS.EMAIL, '@invalid-email')
      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        body: formData,
      })
      await expect(() =>
        strategy.authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        }),
      ).rejects.toThrow(ERRORS.INVALID_EMAIL)
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

    test('Should generate/send TOTP for form email ignoring any form totp code.', async () => {
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

    test.only('Should generate/send TOTP for empty form data with session email.', async () => {
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
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toMatch('/verify')
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
            expect(session.get(SESSION_KEYS.TOTP)).not.toEqual(sessionTotp)
          } else throw reason
        })
        expect(sendTOTP).toHaveBeenCalledTimes(2)
    })

    test.skip('Re-send TOTP - Should invalidate previous TOTP.', async () => {
      updateTOTP.mockImplementation(async (_, { active }) => {
        expect(active).toBe(false)
      })

      const strategy = new TOTPStrategy(TOTP_STRATEGY_OPTIONS, verify)
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
        body: new FormData(), // Empty form data indicates re-send new TOTP.
      })
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
          } else throw reason
        })
      expect(updateTOTP).toHaveBeenCalledTimes(1)
    })
  })

  describe.skip('2nd Authentication Phase', () => {
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
        formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code + i)
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

    test('Should throw an Error on missing TOTP from database.', async () => {
      const { strategy, session, sendTOTPOptions } = await setupFirstAuthPhase({
        readTOTP,
      })
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
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
          successRedirect: '/account',
        }),
      ).rejects.toThrowError(ERRORS.TOTP_NOT_FOUND)
    })

    test('Should throw a custom Error message on missing TOTP from database.', async () => {
      const CUSTOM_ERROR = 'Custom error message.'
      const { strategy, session, sendTOTPOptions } = await setupFirstAuthPhase({
        readTOTP,
        customErrors: { totpNotFound: CUSTOM_ERROR },
      })
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
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
          successRedirect: '/account',
        }),
      ).rejects.toThrowError(CUSTOM_ERROR)
    })

    test('Should throw an Error on inactive TOTP.', async () => {
      const { strategy, session, sendTOTPOptions } = await setupFirstAuthPhase({
        readTOTP: () =>
          Promise.resolve({ hash: 'SIGNED-JWT', attempts: 0, active: false }),
      })
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
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
          successRedirect: '/account',
        }),
      ).rejects.toThrowError(ERRORS.INACTIVE_TOTP)
    })

    test('Should throw an Error on expired TOTP verification.', async () => {
      const { strategy, session, sendTOTPOptions } = await setupFirstAuthPhase()
      vi.setSystemTime(
        new Date(Date.now() + 1000 * 60 * (TOTP_GENERATION_DEFAULTS.period + 1)),
      )
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
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

    test('Should successfully validate TOTP.', async () => {
      const { strategy, session, sendTOTPOptions } = await setupFirstAuthPhase()
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
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
        })
        .catch((reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            expect(reason.headers.get('location')).toBe(`/account`)
          } else throw reason
        })
    })

    test('Should contain user property in session.', async () => {
      const { strategy, session, sendTOTPOptions, user } = await setupFirstAuthPhase()
      const formData = new FormData()
      formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)
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
        })
        .catch(async (reason) => {
          if (reason instanceof Response) {
            expect(reason.status).toBe(302)
            const session = await sessionStorage.getSession(
              reason.headers.get('set-cookie') ?? '',
            )
            expect(session.has('user')).toBeTruthy()
            expect(session.get('user')).toEqual(user)
          } else throw reason
        })
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
        formData.append(FORM_FIELDS.CODE, sendTOTPOptions.code)

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
