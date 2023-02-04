import { test, expect } from 'vitest'
import { getBaseUrl } from '../src/utils'
import { HOST_URL } from './utils'

test('Should properly use `http` protocol for local environments.', async () => {
  const request = new Request(`${HOST_URL}`)
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
  ]

  for (const [host, protocol] of samples) {
    request.headers.set('host', host)
    expect(getBaseUrl(request).startsWith(protocol)).toBe(true)
  }
})
