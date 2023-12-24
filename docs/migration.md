## Migration

This document aims to assist you in migrating your `remix-auth-totp` implementation from `v1` to `v2`.

### Database

Add `expiresAt` field to `Totp` model if it's not already there.

```ts
model Totp {
  hash String @unique
  active Boolean
  attempts Int

  // Add `expiresAt` field.
  expiresAt DateTime
}
```

### Implement `remix-auth-totp` API

- Remove `storeTOTP` and `handleTOTP` from `TOTPStrategy` options.
- Add `createTOTP`, `readTOTP` and `updateTOTP` to `TOTPStrategy` options.

```ts
authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET,

      // ❗`storeTOTP` and `handleTOTP` are no longer needed (removed).

      createTOTP: async (data, expiresAt) => {
        // Create the TOTP data in the database along with `expiresAt`.
        await db.totp.create({ data, expiresAt })
      },
      readTOTP: async (hash) => {
        // Get the TOTP data from the database.
        return await db.totp.findUnique({ where: { hash } })
      },
      updateTOTP: async (hash, data, expiresAt) => {
        // Update the TOTP data in the database.
        // No need to update `expiresAt` since it does not change after createTOTP() is called.
        await db.totp.update({ where: { hash }, data })
      },

      // Unchanged.
      sendTOTP: async ({ email, code, magicLink }) => {},
    },
    // Unchanged.
    async ({ email, code, magicLink, form, request }) => {},
  ),
)
```
