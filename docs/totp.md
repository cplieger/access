# Second factors and temporary passwords

This page explains authenticator-app codes, the recovery code, `RequireSecondFactor`, the admin's reset and the temporary password. Read it before you wire TOTP or choose how users recover an account.

A second factor is a passkey, or a time-based one-time password from an authenticator app: TOTP, [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238). A password sign-in asks for one when the user holds an authenticator app. Under `RequireSecondFactor`, every password sign-in proves a held code or passkey, or binds one first. Passkey sign-ins and single sign-on never ask, since a passkey is already two factors and the identity provider owns the second factor of a single sign-on.

## Setting up TOTP

TOTP is optional. Set `account.Config.TOTP` to wire it, and leave it zero to offer no authenticator apps:

```go
totpSealer, err := access.NewSealer(loadKey("totp.key")) // its own persisted key, shared with no other Sealer
if err != nil {
	log.Fatal(err)
}
cfg.TOTP = account.TOTPConfig{Sealer: totpSealer, Issuer: "My App"}
```

- `Sealer` seals each user's TOTP secret before your store sees it. Keep its key ring for the life of your store, because a secret no key opens cannot check a code.
- `Issuer` is the app's name in the authenticator app. `account.New` refuses an issuer that holds a colon, a sealer with no key, and a value with only one of the two fields set.
- `Rules.DisableTOTP` turns enrolment and the code step off at run time. A stored record is kept and counts as absent until the switch is off again.

The `totp` package does the arithmetic on Go's standard library. A code is six digits from HMAC-SHA-1 over a 30-second step, and a 20-byte secret is drawn for each enrolment. A code from the step before or after the current one is accepted, so one code works for up to 90 seconds. Each accepted code moves the record's `LastStep`, so the same code, or an older one, never works twice.

## Enrolling from a session

The Account screen enrols an authenticator app in two calls, because the person scans a QR code between them.

1. `BeginTOTP` (`authTOTPBegin`) draws a secret and answers it as an `otpauth://` URI for the QR code, as base32 text to type in, and a ticket.
2. `FinishTOTP` (`authTOTPFinish`) takes the ticket and a code from the app, and stores the record.

Enrolling needs a full session signed in within `Rules.RecentAuth`, a secure request and a password on the account. A user with no password gets `ErrPasswordRequired`, answered 403 `auth_forbidden` with reason `totp_needs_password`, because the code is the second factor of a password sign-in. Replacing an existing authenticator app also needs a current code of the old one, sent as `current_code`.

`RemoveTOTP` (`authTOTPRemove`) needs a proof of a current second factor: a code, or a passkey assertion. A user cannot remove their last usable second factor while `RequireSecondFactor` is on. A record that is dormant, because TOTP is unwired or turned off, is removed under recent auth alone. `MethodsView.totp` tells the screen whether the record is `usable` and `removable`.

A user whose password sign-in asks for a second factor steps up with a code or a passkey, never with the password alone. `StepUpCode` (`authStepUpCode`) takes a code, and `MethodsView.password_step_up` tells `withStepUp` whether to offer the password.

## Signing in with a second factor

A correct password from a user who holds a usable TOTP answers a pending sign-in, not a session ([Pending sign-ins](configuration.md#pending-sign-ins) gives the ticket's rules). The ticket's `methods` list the second steps the user may take:

- `totp`: `SignInWithCode` (`authLoginCode`) takes a code.
- `passkey`: `SecondFactorPasskeyBegin` and `SecondFactorPasskeyFinish` (`authLoginSecondPasskeyBegin` and `authLoginSecondPasskeyFinish`) take a passkey assertion.
- `recovery_code`: `SignInWithRecoveryCode` (`authLoginRecoveryCode`) takes the recovery code, described below.

Each wrong code counts against the account in the code's own failure record, before the code is compared. After 100 consecutive failures the authenticator app is locked for that account in that trust context, as a password is. A correct code clears the count. The person signed in another way re-enables it with `ReenableMethod`. The first refused second step of a ticket appends `second_factor_failed` to the [security log](security-log.md), because someone holding the right password failed it.

A record whose sealer key is gone cannot check any code. It answers 503 `auth_second_factor_unavailable`, is logged at ERROR and counts as no failure. The user's way back is the recovery code or an admin's reset.

## The recovery code

A user whose password sign-in asks for a second factor holds one recovery code, the saved recovery code of [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) section 4.2.1.1. That is a password user with a usable TOTP, or, under `RequireSecondFactor`, with a usable passkey. The code holds 80 random bits, shown as `XXXX-XXXX-XXXX-XXXX` in [Crockford's base32](https://www.crockford.com/base32.html), and is stored only as a salted hash from the password hasher.

- A change that leaves such a user with no recovery code issues one. That is a `FinishTOTP`, the enrolment that ends a pending sign-in, and, under `RequireSecondFactor`, a passkey added from Account or a first password. The answer of that change carries it once, in `recovery_code`.
- At a pending sign-in, `SignInWithRecoveryCode` accepts it in place of the lost factor and answers a new pending step that enrols a new authenticator app or passkey. Only that enrolment spends the code, deletes the lost TOTP, binds the new factor and shows a new recovery code in `SignedInResponse.recovery_code`. An abandoned recovery leaves the old code and the old TOTP in place.
- `RegenerateRecoveryCode` (`authRecoveryCodeRegenerate`) replaces it, with a proof of a current second factor.
- Each wrong code counts against the account in the recovery code's own failure record, before the code is compared, and 100 consecutive failures lock it in that trust context. A correct code clears the count, even when the enrolment after it is abandoned.
- On input, dashes, spaces and letter case do not matter, `O` reads as `0`, and `I` and `L` read as `1`. A value holding any other character is refused as malformed and is not counted.

A passkey-only user gets no recovery code, since no step accepts one without a password. That user's recovery is an admin's temporary password, described below. NIST section 4.2.1 allows such a method when the service documents its risk analysis. Here an admin hands the secret over by hand, and it lives 24 hours by default. Its first correct entry spends it, and its issue is logged and can be notified. Ask passkey-only users to register a second passkey, as the FIDO Alliance advises.

## Requiring a second factor

`Rules.RequireSecondFactor` makes every password sign-in prove a second factor, or bind one first. It needs `Config.TOTP` or `Config.RP` set, and `account.New`, every operation and `Service.CheckRules` refuse it otherwise.

- A user who holds no second factor reaches the enrolment step at their next password sign-in, from a known device only: a browser whose device cookie a secure sign-in sealed. From a new browser, step 1 answers 403 `auth_second_factor_required` with reason `enrol_needs_known_device`. A stolen password then cannot bind the thief's own authenticator, and the person asks an admin for a temporary password.
- Setup, invite acceptance and registration by password create the account only when the second factor is bound, so an abandoned enrolment leaves nothing behind.
- Before your settings screen saves the rule on, call `Service.CheckSecondFactorReady`. It refuses with reason `enable_without_second_factor` unless the admin making the change holds a usable second factor.
- Sessions that exist when the rule turns on keep their life.

A deployment reached only over plain HTTP cannot use the rule, because enrolment needs HTTPS. Every way back, a reset or a temporary password included, ends at an enrolment that plain HTTP refuses, so turn the rule off there. Each `auth_https_required` the rule causes logs a WARN that names it.

## Over plain HTTP

Under `PosturePerRequest`, the code step is allowed over plain HTTP, so a TOTP user on a plain-only network can still sign in. There the code stops a password reused from elsewhere or stuffed from a breach. It does not stop a reader on the network, who sees the session token in the very response the code earns. It is not the protected channel NIST SP 800-63B-4 section 3.1.4.2 requires, so treat a plain network as one whose observers you trust. Enrolment, the passkey step and the recovery-code step need HTTPS ([Plain HTTP](plain-http.md)).

## The admin's reset

`ResetSecondFactor` (`authAdminSecondFactorReset`) is for a lost phone whose passkeys are still the user's. It deletes the user's TOTP record and recovery code, ends their sessions and pending sign-ins, clears both locks and appends `second_factor_reset`. The password, passkeys and API keys stay.

- An admin, an API key with `ManageUsersScope` on a regular user, or an out-of-band caller such as an admin socket may reset. A key presenting the secret a rotation superseded is refused with `key_retiring`. Only another owner or an out-of-band caller resets an owner, and `SingleOwnerPolicy` allows the out-of-band caller only.
- Nobody resets their own second factor this way. They remove it from Account with a current factor, or a single owner uses the admin socket.
- A user holding neither record answers `ErrNotFound`, and nothing is written.

For a lost device that held passkeys, issue a temporary password with `RevokePasskeys` set.

## The temporary password

An admin makes a user, or lets one back in, with a temporary password. `SetTemporaryPassword` (`authAdminTemporaryPassword`) issues one and answers it once. The person enters it on the ordinary sign-in form, and the sign-in answers a pending step that sets their own credential, never a session.

The secret is 16 characters of Crockford's base32, shown as `XXXX-XXXX-XXXX-XXXX`: 64 random bits and the low 16 bits of their CRC-32. The check protects nothing. It lets the sign-in screen recognise a temporary password without asking the server. It lives 24 hours by default and 7 days at most, and one an API key issued expires no later than the key.

### Issuing

- An admin, an API key with `ManageUsersScope` on a regular user, or an out-of-band caller may issue one. Owners are issued one only by another owner or an out-of-band caller, and `SingleOwnerPolicy` allows the out-of-band caller only.
- Nobody issues one for themselves. The refusal's reason is `self_recovery`.
- Issuing is refused over plain HTTP, because the answer is a new secret. A plain-only network's way is the admin socket, as an out-of-band caller.
- Issuing replaces any earlier temporary password, clears the user's password, TOTP and recovery code, deletes their API keys and the links those keys issued, and ends their sessions, pending sign-ins and locks. `KeepKeys` keeps the keys, and `RevokePasskeys` also deletes the passkeys.
- Under `account.SSOOnly`, an unlinked account other than an owner's keeps its password, TOTP and recovery code, which are dormant. Its temporary password's one use is the admin link ([Identity and single sign-on](identity.md#linking-with-an-admins-consent)).
- Under `SSOForLinked` and `SSOOnly`, a linked account other than an owner's is refused with 403 `auth_sso_only` and reason `linked`, because it signs in only by single sign-on. For an identity that changed hands, use `AdminRelinkOIDC` ([Unlinking](identity.md#unlinking)).

The answer's `https_only` is true when the app also serves plain HTTP and the secret works only on the HTTPS address: `RequireSecondFactor` is on, password sign-in is off, or the SSO mode is `SSOOnly`. Show the HTTPS address with the secret when it is. An app's admin socket reads the same fact from `Service.TemporaryPasswordHTTPSOnly`.

### Using it

- The sign-in form checks a live temporary password first, normalised as a recovery code is. A correct one is spent at once, so its first correct entry is its only one.
- The pending step that follows offers `password` and `passkey`. `SetCredentialPassword` (`authLoginSetPassword`) checks the chosen password as every password write does, and refuses the temporary password itself with reason `is_temporary_password`. `SetCredentialPasskeyBegin` and `SetCredentialPasskeyFinish` register a passkey instead.
- Under `RequireSecondFactor`, the chosen password is written only with the second factor the next step enrols. An abandoned enrolment leaves the account with no password, and the person needs a new temporary password.
- Under `Rules.DisablePasswordLogin`, the form still accepts a live temporary password, and the next step offers only `passkey`. An app whose recovery verb issues a temporary password while password sign-in is off turns it back on with the issue, so the secret leads to a password.
- An issuer that is gone, disabled or no longer allowed to issue makes the secret fail as a wrong password, and the record is deleted. One issued out of band has no issuer to check.

### Over plain HTTP

A plain sign-in that verifies a temporary password and cannot finish deletes it, because the secret has just crossed the network in clear. That happens under `RequireSecondFactor`, under `DisablePasswordLogin`, under an SSO mode that keeps the user's local methods dormant, and when your rules leave the next step no method. The answer is 403 `auth_https_required` with reason `temporary_password_exposed`, or a wrong-password answer for an account the SSO mode refuses. The log entry `temporary_password_used` carries `plain`, so an app with a notification channel can tell the account's holder.

`StateResponse.temporary_password_https_only` tells a plain sign-in screen to keep the secret off the network. The screen then offers no temporary-password entry, says the temporary password works only on the HTTPS address, and refuses to send a value `looksLikeTemporaryPassword` recognises. Its copy says "If this is your password, sign in on `https://<host>`." and offers no way to send it anyway, because the HTTPS address always exists there.

The recogniser catches the displayed form anywhere in the value, a 16-character run whose check passes, and any value one edit from a temporary password. Measured on random passwords, it also takes about one 15- or 16-character password in 200 for a temporary one, and about one in 1,000 at 128 characters. It takes one diceware passphrase in 500 at four words and one in 150 at seven. Those hold two four-letter words in a row between two words of four letters or more, such as "tree bird fish wolf".

It does not catch a value two or more edits away, such as a dashed secret with two characters dropped from different groups, or one typo in the undashed secret inside other text. A client that is not a browser can also send the secret anyway. Type a temporary password only on the HTTPS address.

One request at a time verifies a name's temporary password, so two correct entries get one sign-in. A reader who replays a plain request at once on another connection can still win that race. If someone else redeemed a temporary password, issue a new one with `RevokePasskeys` set.

## Rotating the TOTP sealer key

1. Put the new key first in the sealer's ring, keep the old one after it, and restart.
2. Run `Service.ResealTOTP`. It re-seals each record under the first key, each in its own transaction, so a sign-in during the walk keeps its last step. Records the first key already opens are left alone.
3. Drop the old key and restart.

`ResealTOTP` stops at the first store error and returns it with the counts so far. A nil error means the walk reached the last record, and every record that existed then and opens is sealed under the first key. `unopenable` counts the records no key opens, each logged at ERROR with its user ID. A record written during the walk is sealed under the first key already, since every write seals under it. Those users recover with their recovery code or an admin's reset.

## Notifications

NIST SP 800-63B-4 section 4.6 requires telling the account's holder when an authenticator is bound, when an account is recovered and when a recovery code is replaced. access stores no address and sends nothing. The security log is the local record, and `Config.OnEvent` is where an app with a channel, such as email or a push service, sends the notice. Send one on each of these kinds:

- `password_set`, `password_changed`, `password_removed`
- `totp_added`, `totp_replaced`, `totp_removed`
- `passkey_added`, `passkey_removed`
- `recovery_code_issued`, `recovery_code_used`, `recovery_code_replaced`
- `second_factor_reset`
- `temporary_password_set`, `temporary_password_used`, `temporary_password_withdrawn`

A `temporary_password_used` with `plain` set is the exposure notice. An app with no channel does not meet section 4.6.
