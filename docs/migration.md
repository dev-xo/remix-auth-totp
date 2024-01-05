## Migration

This document aims to assist you in migrating your `remix-auth-totp` implementation from `v2` to `v3`.

### Database

Remove `Totp` model from database if one exists.

### Implement `remix-auth-totp` API

- Remove `createTOTP`, `readTOTP` and `updateTOTP` from `TOTPStrategy` options.

```ts
authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET,

      // ❗`createTOTP`, `readTOTP` and `updateTOTP` are no longer needed (removed).

      // Unchanged.
      sendTOTP: async ({ email, code, magicLink }) => {},
    },
    // Unchanged.
    async ({ email, code, magicLink, form, request }) => {},
  ),
)
```
