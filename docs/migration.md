## Migration

This document aims to assist you in migrating your `remix-auth-totp` implementation from `v2` to `v3`.

### Database

Remove `Totp` model from database if one exists.

### Implement `remix-auth-totp` API

- Remove `createTOTP`, `readTOTP` and `updateTOTP` from `TOTPStrategy` options.
- Remove unneeded parameters from `sendTOTP` and `verify` functions

```ts
authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET,

      // ❗`createTOTP`, `readTOTP` and `updateTOTP` are no longer needed (removed).

      // Only email, code, and magicLink. Remove any other parameters.
      sendTOTP: async ({ email, code, magicLink }) => {},
    },
    // Only email. Remove any other parameters.
    async ({ email }) => {},
  ),
)
```
