import type { CodeGenerationOptions, MagicLinkGenerationOptions } from './index'
import crypto from 'crypto-js'
import otpGenerator from 'otp-generator'

/**
 * Encryption.
 */
export async function encrypt(value: string, secret: string): Promise<string> {
  return crypto.AES.encrypt(value, secret).toString()
}

export async function decrypt(value: string, secret: string): Promise<string> {
  const bytes = crypto.AES.decrypt(value, secret)
  return bytes.toString(crypto.enc.Utf8)
}

/**
 * OTP Generation.
 */
export function generateOtp(options: CodeGenerationOptions) {
  const code = otpGenerator.generate(options.length, { ...options })
  const createdAt = new Date().toISOString()

  return {
    code,
    createdAt,
  }
}

/**
 * Magic Link Generation.
 */
export function generateMagicLink(
  options: MagicLinkGenerationOptions & {
    param: string
    code: string
    request: Request
  },
) {
  if (!options.enabled) {
    return undefined
  }

  const url = new URL(
    options.callbackPath ?? '/',
    options.baseUrl ?? getBaseUrl(options.request),
  )
  url.searchParams.set(options.param, options.code)

  return url.toString()
}

/**
 * Helpers.
 */
export function getBaseUrl(request: Request) {
  const host = request.headers.get('X-Forwarded-Host') ?? request.headers.get('host')

  if (!host) {
    throw new Error('Could not determine host.')
  }

  // If the host is localhost or ends with .local, use http.
  const protocol = host.match(/(:?\.local|^localhost|^127\.\d+\.\d+\.\d+)(:?:\d+)?$/)
    ? 'http'
    : 'https'

  return `${protocol}://${host}`
}
