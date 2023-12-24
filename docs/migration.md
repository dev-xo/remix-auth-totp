## Migration

Migrating from v1 to v2

### Database

Add `expiresAt` field to `Totp` model if it's not already there.

```ts
model Totp {
  hash String @unique
  active Boolean
  attempts Int

  // Add expiresAt field
  expiresAt DateTime
}
```

### Implement `remix-auth-totp` API

- Remove `storeTOTP` and `handleTOTP`.
- Add `createTOTP`, `readTOTP` and `updateTOTP`.

```ts
authenticator.use(
  new TOTPStrategy(
    {
      secret: process.env.ENCRYPTION_SECRET,

      // storeTOTP and handleTOTP deleted.

      createTOTP: async (data, expiresAt) => {
        // Create the TOTP data in the database along with expiresAt.
        await db.totp.create({ data, expiresAt })
      },
      readTOTP: async (hash) => {
        // Get the TOTP data from the database.
        return await db.totp.findUnique({ where: { hash } })
      },
      updateTOTP: async (hash, data, expiresAt) => {
        // Update the TOTP data in the database.
        // No need to update expiresAt since it does not change after createTOTP().
        await db.totp.update({ where: { hash }, data })
      },

      // Unchanged
      sendTOTP: async ({ email, code, magicLink }) => {},
    },
    // Unchanged
    async ({ email, code, magicLink, form, request }) => {},
  ),
)
```
