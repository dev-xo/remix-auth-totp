## Migration

This document aims to assist you in migrating your `remix-auth-totp` implementation from `v2` to `v3`.

### Database

Remove `Totp` model from database if one exists.

### Implement `remix-auth-totp` API

- Remove `createTOTP`, `readTOTP` and `updateTOTP` from `TOTPStrategy` options.
- Remove unneeded parameters from `verify` function

```ts
authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET,

      // ❗`createTOTP`, `readTOTP` and `updateTOTP` are no longer needed (removed).

      sendTOTP: async ({ email }) => {},
    },
    // Only email. Remove any other parameters.
    async ({ email }) => {},
  ),
)
```
