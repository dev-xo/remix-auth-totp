## Cloudflare

A guide to using Remix Auth TOTP with Cloudflare Pages.

### AppLoadContext

If you need `context` to be populated with the `AppLoadContext` in `SendTOTPOptions` or `TOTPVerifyParams`, be sure to include it in the call to `authenticate` on the remix-auth `Authenticator`.

```ts
await authenticator.authenticate('TOTP', request, {
  successRedirect: '/verify',
  failureRedirect: new URL(request.url).pathname,
  context: appLoadContext,
})
```

### Using Cloudflare KV for Session Storage

```ts
const sessionStorage = createWorkersKVSessionStorage({
  kv: KV,
  cookie: {
    name: '_auth',
    path: '/',
    sameSite: 'lax',
    httpOnly: true,
    secrets: [SESSION_SECRET],
    secure: ENVIRONMENT === 'production',
  },
})

const authenticator = new Authenticator<SessionUser>(sessionStorage)

authenticator.use(
  new TOTPStrategy(
    {
      secret: TOTP_SECRET,
      sendTOTP: async ({ email, code, magicLink }) => {},
    },
    async ({ email }) => {},
  ),
)
```

## Contributing

If you have any suggestions you'd like to share, feel free to open a PR!
