# Configurable OIDC email claim

Goal: Allow operators to issue a generated email claim instead of a user's real email address, using the user's main character ID and a configured domain.

## Implementation

- [x] Add an optional `ALLIANCEAUTH_OIDC_EMAIL_DOMAIN` Django setting. When unset, keep the current `request.user.email` behavior; when set to `example.invalid`, issue `<main_character_id>@example.invalid` (for example, `123456@example.invalid`). No separate enable flag or database migration is needed.
- [x] Update the `email` claim in `AllianceAuthOAuth2Validator` to use `request.user.profile.main_character.character_id` in generated mode. Keep the existing `email` scope mapping and other claims unchanged.
- [x] Validate that the setting is a bare domain name, not a URL, address, or value containing whitespace. Reject invalid nonempty configuration rather than issuing malformed addresses.
- [x] In generated mode, if the user has no main character, omit the email claim instead of exposing their real address. Do not silently fall back to `request.user.email`.

## Verification

- [x] Test the default real-email behavior and generated `<main_character_id>@<domain>` behavior with the existing test fixtures.
- [x] Test that the generated address is present only with the `email` scope, in both an ID token and a UserInfo response, and that the real email is not leaked.
- [x] Test invalid domain configuration and a user without a main character; generated mode must never expose the real email in either case.
- [x] Run the package's Django tests using `tests.test_settingsAA4` and check for regressions.

## Documentation

- [x] Document the setting, its default, an example configuration, and the generated email format in `README.md`.
- [x] Note that generated addresses need not be deliverable and will change if a user changes their main character. Relying parties should use the stable OIDC `sub` claim to identify users.
