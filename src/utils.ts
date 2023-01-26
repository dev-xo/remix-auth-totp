import type { CodeGenerationOptions } from './index'
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
 * OTP.
 */
export function generateOtp(options: CodeGenerationOptions) {
  const code = otpGenerator.generate(options.length, { ...options })
  const createdAt = new Date().toISOString()

  return {
    code,
    createdAt,
  }
}
