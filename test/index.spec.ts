import { describe, test, expect, afterEach, vi } from 'vitest';
import { AuthorizationError } from 'remix-auth';

import { TOTPStrategy } from '../src/index';
import { generateTOTP, generateMagicLink, getHostUrl, signJWT } from '../src/utils';
import { STRATEGY_NAME, FORM_FIELDS, SESSION_KEYS, ERRORS } from '../src/constants';

import {
  SECRET_ENV,
  HOST_URL,
  AUTH_OPTIONS,
  TOTP_GENERATION_DEFAULTS,
  MAGIC_LINK_GENERATION_DEFAULTS,
  DEFAULT_EMAIL,
  sessionStorage,
} from './utils';

/**
 * Mocks.
 */
export const verify = vi.fn();
export const storeTOTP = vi.fn();
export const sendTOTP = vi.fn();
export const handleTOTP = vi.fn();
export const validateEmail = vi.fn();

afterEach(() => {
  vi.restoreAllMocks();
});

describe('[ Basics ]', () => {
  test('Should contain the name of the Strategy.', async () => {
    const strategy = new TOTPStrategy(
      { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
      verify,
    );

    expect(strategy.name).toBe(STRATEGY_NAME);
  });

  test('Should throw an Error on missing required secret option.', async () => {
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
    });

    // @ts-expect-error - Error is expected.
    const strategy = new TOTPStrategy({ storeTOTP, sendTOTP, handleTOTP }, verify);
    const result = await strategy
      .authenticate(request, sessionStorage, { ...AUTH_OPTIONS, throwOnError: true })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError(ERRORS.REQUIRED_ENV_SECRET));
  });

  test('Should throw an Error on missing required successRedirect option.', async () => {
    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
    });

    const strategy = new TOTPStrategy(
      { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
      verify,
    );
    const result = await strategy
      .authenticate(request, sessionStorage, { ...AUTH_OPTIONS, throwOnError: true })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError(ERRORS.REQUIRED_SUCCESS_REDIRECT_URL));
  });

  test('Should throw a custom Error message.', async () => {
    const CUSTOM_ERROR = 'Custom error message.';

    const formData = new FormData();
    formData.append(FORM_FIELDS.EMAIL, '');

    const request = new Request(`${HOST_URL}`, {
      method: 'POST',
      headers: { host: HOST_URL },
      body: formData,
    });

    const strategy = new TOTPStrategy(
      {
        secret: SECRET_ENV,
        storeTOTP,
        sendTOTP,
        handleTOTP,
        customErrors: {
          requiredEmail: CUSTOM_ERROR,
        },
      },
      verify,
    );
    const result = await strategy
      .authenticate(request, sessionStorage, {
        ...AUTH_OPTIONS,
        throwOnError: true,
        successRedirect: '/',
      })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError(CUSTOM_ERROR));
  });
});

describe('[ TOTP ]', () => {
  describe('1st Authentication Phase', () => {
    test('Should throw an Error on missing formData email.', async () => {
      const formData = new FormData();
      formData.append(FORM_FIELDS.EMAIL, '');

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error);

      expect(result).toEqual(new AuthorizationError(ERRORS.REQUIRED_EMAIL));
    });

    test('Should throw an Error on invalid form email.', async () => {
      const formData = new FormData();
      formData.append(FORM_FIELDS.EMAIL, '@invalid-email');

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error);

      expect(result).toEqual(new AuthorizationError(ERRORS.INVALID_EMAIL));
    });

    test('Should call storeTOTP function.', async () => {
      const formData = new FormData();
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error);

      expect(storeTOTP).toHaveBeenCalledTimes(1);
    });

    test('Should call sendTOTP function.', async () => {
      const formData = new FormData();
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error);

      expect(sendTOTP).toHaveBeenCalledTimes(1);
    });

    test('Should contain auth:email and auth:totp properties in session.', async () => {
      const formData = new FormData();
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      const session = await sessionStorage.getSession(
        result.headers.get('set-cookie') ?? '',
      );

      expect(session.data).toHaveProperty(SESSION_KEYS.EMAIL);
      expect(session.data).toHaveProperty(SESSION_KEYS.TOTP);
    });

    test('Should contain Location header pointing to provided successRedirect url.', async () => {
      const formData = new FormData();
      formData.append(FORM_FIELDS.EMAIL, DEFAULT_EMAIL);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/verify',
        })
        .catch((error) => error)) as Response;

      expect(result.headers.get('location')).toMatch('/verify');
    });

    test('Re-send TOTP - Should invalidate previous TOTP.', async () => {
      const mockedStoreTOTP = storeTOTP.mockImplementation(() =>
        Promise.resolve('JWT-Signed'),
      );
      const signedTotp = await mockedStoreTOTP();

      const formData = new FormData();
      const session = await sessionStorage.getSession();

      session.set(SESSION_KEYS.EMAIL, DEFAULT_EMAIL);
      session.set(SESSION_KEYS.TOTP, signedTotp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          host: HOST_URL,
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP, validateEmail },
        verify,
      );
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          successRedirect: '/',
        })
        .catch((error) => error);

      // Called 2 times:
      // - 1st: Inside 'Re-send TOTP'.
      // - 2nd: Inside 'First TOTP request' after storing the TOTP.
      expect(handleTOTP).toHaveBeenCalledTimes(2);
      expect(validateEmail).toHaveBeenCalledTimes(1);
    });
  });

  describe('2nd Authentication Phase', () => {
    test('Should invalidate current TOTP.', async () => {
      const totp = generateTOTP(TOTP_GENERATION_DEFAULTS);
      const formData = new FormData();
      formData.append(FORM_FIELDS.TOTP, totp.otp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error);

      expect(handleTOTP).toHaveBeenCalledTimes(1);
    });

    test('Should throw an Error on missing TOTP from database.', async () => {
      const totp = generateTOTP(TOTP_GENERATION_DEFAULTS);
      const formData = new FormData();
      formData.append(FORM_FIELDS.TOTP, totp.otp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      expect(result).toEqual(new AuthorizationError(ERRORS.TOTP_NOT_FOUND));
    });

    test('Should throw an Error on inactive TOTP.', async () => {
      handleTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: false }),
      );

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS);
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      });

      const formData = new FormData();
      formData.append(FORM_FIELDS.TOTP, _otp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      expect(result).toEqual(new AuthorizationError(ERRORS.INACTIVE_TOTP));
    });

    test('Should throw an Error on max TOTP attempts.', async () => {
      handleTOTP.mockImplementation(() =>
        Promise.resolve({
          hash: signedTotp,
          attempts: TOTP_GENERATION_DEFAULTS.maxAttempts,
          active: true,
        }),
      );

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS);
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      });

      const formData = new FormData();
      formData.append(FORM_FIELDS.TOTP, _otp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: { host: HOST_URL },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      expect(result).toEqual(new AuthorizationError(ERRORS.INACTIVE_TOTP));
    });

    test('Should throw an Error on invalid (expired) JWT.', async () => {
      handleTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: true }),
      );

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS);
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: 0,
        secretKey: SECRET_ENV,
      });

      const formData = new FormData();
      formData.append(FORM_FIELDS.TOTP, _otp);

      const session = await sessionStorage.getSession();
      session.set(SESSION_KEYS.TOTP, signedTotp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          host: HOST_URL,
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      expect(result).toEqual(new AuthorizationError(ERRORS.INACTIVE_TOTP));
    });

    test('Should throw an Error on invalid (expired) TOTP verification.', async () => {
      handleTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: true }),
      );

      const { otp: _otp, ...totp } = generateTOTP({
        ...TOTP_GENERATION_DEFAULTS,
        period: 0.1,
      });
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      });

      const formData = new FormData();
      formData.append(FORM_FIELDS.TOTP, _otp);

      const session = await sessionStorage.getSession();
      session.set(SESSION_KEYS.TOTP, signedTotp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          host: HOST_URL,
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      });

      // Wait for TOTP expiration.
      await new Promise((resolve) => {
        setTimeout(() => {
          resolve(true);
        }, 200);
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      expect(result).toEqual(new AuthorizationError(ERRORS.INVALID_TOTP));
    });

    test('Should throw an Error on invalid (expired) magic-link TOTP verification.', async () => {
      handleTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: true }),
      );

      const { otp: _otp, ...totp } = generateTOTP({
        ...TOTP_GENERATION_DEFAULTS,
        period: 0.1,
      });
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      });

      const magicLink = generateMagicLink({
        ...MAGIC_LINK_GENERATION_DEFAULTS,
        callbackPath: '/magic-link',
        param: 'code',
        code: _otp,
        request: new Request(HOST_URL, {
          headers: { host: HOST_URL },
        }),
      });

      const session = await sessionStorage.getSession();
      session.set(SESSION_KEYS.TOTP, signedTotp);

      const request = new Request(`${magicLink}`, {
        method: 'GET',
        headers: {
          host: HOST_URL,
          cookie: await sessionStorage.commitSession(session),
        },
      });

      // Wait for TOTP expiration.
      await new Promise((resolve) => {
        setTimeout(() => {
          resolve(true);
        }, 200);
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      expect(result).toEqual(new AuthorizationError(ERRORS.INVALID_TOTP));
    });

    test('Should throw an Error on invalid magic-link callback path.', async () => {
      const { otp: _otp } = generateTOTP(TOTP_GENERATION_DEFAULTS);

      const magicLink = generateMagicLink({
        ...MAGIC_LINK_GENERATION_DEFAULTS,
        callbackPath: '/invalid',
        param: 'code',
        code: _otp,
        request: new Request(HOST_URL, {
          headers: { host: HOST_URL },
        }),
      });

      const request = new Request(`${magicLink}`, {
        method: 'GET',
        headers: { host: HOST_URL },
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      expect(result).toEqual(new AuthorizationError(ERRORS.INVALID_MAGIC_LINK_PATH));
    });

    test('Should successfully validate TOTP.', async () => {
      handleTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: true }),
      );

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS);
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      });

      const formData = new FormData();
      formData.append(FORM_FIELDS.TOTP, _otp);

      const session = await sessionStorage.getSession();
      session.set(SESSION_KEYS.TOTP, signedTotp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          host: HOST_URL,
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      expect(result.status).toBe(302);
      expect(result.headers.get('location')).toMatch('/');
    });

    test('Should contain user property in session.', async () => {
      handleTOTP.mockImplementation(() =>
        Promise.resolve({ hash: signedTotp, attempts: 0, active: true }),
      );
      verify.mockImplementation(() => Promise.resolve({ name: 'John Doe' }));

      const { otp: _otp, ...totp } = generateTOTP(TOTP_GENERATION_DEFAULTS);
      const signedTotp = await signJWT({
        payload: totp,
        expiresIn: TOTP_GENERATION_DEFAULTS.period,
        secretKey: SECRET_ENV,
      });

      const formData = new FormData();
      formData.append(FORM_FIELDS.TOTP, _otp);

      let session = await sessionStorage.getSession();
      session.set(SESSION_KEYS.TOTP, signedTotp);

      const request = new Request(`${HOST_URL}`, {
        method: 'POST',
        headers: {
          host: HOST_URL,
          cookie: await sessionStorage.commitSession(session),
        },
        body: formData,
      });

      const strategy = new TOTPStrategy(
        { secret: SECRET_ENV, storeTOTP, sendTOTP, handleTOTP },
        verify,
      );
      const result = (await strategy
        .authenticate(request, sessionStorage, {
          ...AUTH_OPTIONS,
          throwOnError: true,
          successRedirect: '/',
        })
        .catch((error) => error)) as Response;

      session = await sessionStorage.getSession(result.headers.get('set-cookie') ?? '');

      expect(session.data).toHaveProperty('user');
      expect(session.data.user.name).toBe('John Doe');
    });
  });
});

describe('[ Utils ]', () => {
  test('Should properly use the HTTP protocol for local environments.', async () => {
    const request = new Request(`${HOST_URL}`);
    const samples: Array<[string, 'http:' | 'https:']> = [
      ['127.0.0.1', 'http:'],
      ['127.1.1.1', 'http:'],
      ['127.0.0.1:8888', 'http:'],
      ['localhost', 'http:'],
      ['localhost:3000', 'http:'],
      ['remix.run', 'https:'],
      ['remix.run:3000', 'https:'],
      ['local.com', 'https:'],
      ['legit.local.com:3000', 'https:'],
      ['remix-auth-otp.local', 'http:'],
      ['remix-auth-otp.local:3000', 'http:'],
    ];

    for (const [host, protocol] of samples) {
      request.headers.set('host', host);
      expect(getHostUrl(request).startsWith(protocol)).toBe(true);
    }
  });
});
