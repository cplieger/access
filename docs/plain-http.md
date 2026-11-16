# Plain HTTP

access can serve a request that crossed a network in clear, such as a LAN address an instance answers without TLS. This page says what such a request may do under each cookie posture, how API keys and your own routes fit in, and what binding a session to its transport protects. Read it before you serve plain HTTP, or before you choose a posture.

A request is plain when the `ClientAddr.Secure` your resolver answers is false, and secure when TLS ended at your server or at a proxy you trust ([Authenticator configuration](configuration.md#authenticator-configuration)). `account` reads the same fact from `Client.Secure` and `Principal.Secure`, so a `Client` or `Principal` you build without `Secure` is plain and is refused where plain requests are.

## The two postures

The posture is `CookieConfig.Posture`, and it is the only switch ([Session cookie](configuration.md#session-cookie) gives each posture's cookie names).

- `PostureSecure`, the default, is HTTPS only. `Authenticate` refuses every plain request with 403 `auth_https_required` ([Session cookie](configuration.md#session-cookie) says where in the chain). Every `account` operation that takes a `Client` refuses a plain one too, sign-in and setup included. `State` and `Logout` are the two exceptions: `State` answers what the sign-in screen needs, and `Logout` only ends a session. Run it when every client reaches the app over HTTPS.
- `PosturePerRequest` serves both. A secure request may do everything, and a plain one gets the policy below. Run it for one instance that serves plain-HTTP LAN clients and HTTPS clients through a proxy.

## What a plain request may do

Under `PosturePerRequest`, a plain request may sign in and set up the first account by password, and use what a password session can use. It gets no other sign-in ceremony, no step-up, no removal of the one method a plain session signs in with, no operation that answers a newly issued long-lived secret, and no change of the SSO mode.

| Allowed over plain HTTP | Refused over plain HTTP with 403 `auth_https_required` |
| --- | --- |
| `authState`, `authSetupPassword` (with `RequireSecondFactor` off, since under it setup enrols a second factor, which needs HTTPS), `authLoginPassword` (a temporary password whose next step needs HTTPS, under `RequireSecondFactor` or with password sign-in off, is cancelled and answers `auth_https_required` with reason `temporary_password_exposed`; one the SSO mode refuses is cancelled and answers as a wrong password), `authLoginCode`, `authLoginSetPassword` (on a ticket a plain step 1 minted, with `RequireSecondFactor` off, since under it the password set leads to an enrolment, which needs HTTPS), `authLogout` | `authSetupPasskeyBegin`, `authSetupPasskeyFinish`, `authLoginPasskeyBegin`, `authLoginPasskeyFinish`, `authLoginSecondPasskeyBegin`, `authLoginSecondPasskeyFinish`, `authLoginSetPasskeyBegin`, `authLoginSetPasskeyFinish`, `authLoginRecoveryCode` (before the code is read, since the enrolment that follows needs HTTPS), `authPendingTOTPBegin`, `authPendingTOTPFinish`, `authPendingPasskeyBegin`, `authPendingPasskeyFinish` |
| `authMe`, `authProfile`, `authMethodReenable` | every OIDC route: `authOIDCStartSignIn`, `authOIDCStartLink`, `authOIDCStartStepUp`, `authInviteAcceptOIDC`, `authOIDCCallback`, `authOIDCPending`, `authOIDCCreatePending`, `authOIDCLinkByAdmin`, `authOIDCLinkPending` |
| `authPasswordSet`, whose recent auth is the sign-in's time | `authStepUpPassword`, `authStepUpCode`, `authStepUpPasskeyBegin`, `authStepUpPasskeyFinish` |
| `authPasskeys`, `authPasskeyRename`, `authPasskeyRemove` with a code as its proof, `authTOTPRemove`, `authWebAuthnSignals`, `authOIDCUnlink` | `authPasswordRemove`, `authTOTPBegin`, `authTOTPFinish`, `authRecoveryCodeRegenerate` |
| `authSessions`, `authSessionRename`, `authSessionRevoke`, `authSessionsRevokeOthers` | `authPasskeyRegisterBegin`, `authPasskeyRegisterFinish` |
| `authKeys`, `authKeyRename`, `authKeyRevoke`, `authAdminKeys`, `authAdminKeyRevoke` | `authInviteAcceptPassword`, `authRegisterPassword`, `authRegisterPasskeyBegin`, `authRegisterPasskeyFinish` |
| `authAdminUsers`, `authAdminUserCreate`, `authAdminUserUpdate`, `authAdminOwner`, `authAdminUserDelete`, `authAdminOIDCUnlink`, `authAdminSecondFactorReset`, `authAdminTokens`, `authAdminSecurityLog` | `authAdminSSOReadiness`, `authAdminSSOApply` |
| every route of yours on the gate, by its class, except a row marked `HTTPS` | `authKeyCreate`, `authKeyRotate`, `authAdminInvite`, `authAdminTemporaryPassword`, `authAdminOIDCRelink` (an admin socket's recovery verb is the plain-only path) |

Four rows need a reason:

- **Reading and changing the SSO mode are refused.** A change moves every account's way in, so only an owner on a secure request makes it, and the readiness read answers the refusals the change would.
- **Removing the password is refused.** Over plain HTTP the password is the session's only way back in, since every other sign-in method needs HTTPS.
- **The code step is allowed, and the other second steps are not.** Over plain HTTP the code stops remote password reuse, but anyone on the path reads the session token in the response the code earns. A passkey assertion, and a passkey proof sent with a removal, need HTTPS, as every passkey ceremony does. A pending sign-in's ticket is bound to the transport that minted it: a plain ticket finishes only over plain HTTP, and a secure ticket presented over plain HTTP is cancelled, since it crossed in clear.
- **Creating a user is allowed.** It answers no secret, and the new user's password is exposed exactly as a password change's is.

`account` enforces the table, so an app that calls it directly gets the same answers: each operation's godoc names its plain answer. An `OutOfBand` actor has no transport and is never refused. An operation that takes both a `Client` and a `Principal` needs both to be secure. In `account` the refusal comes before any other check, limiter charge or store read, so a refused plain request costs nothing and its answer does not depend on its input. `accesshttp` and the gate only translate `access.ErrHTTPSRequired` into the code, and keep no copy of the table.

Each OIDC route is admitted by `account` before it touches a cookie or the identity provider: the sign-in and invite starts, the callback and the pending-link read through `Service.AdmitOIDC`, and the link and step-up starts through `Service.AdmitOIDCSession`. A plain start therefore sets no flow cookie and sends the browser nowhere. A plain pending-link read answers 403 even when it presents a valid pending cookie, which it neither reads nor clears.

## The plain session

A session signed in over plain HTTP is plain: its `Session.Secure` is false, and only a plain request may present it ([What the binding protects](#what-the-binding-protects-and-what-it-does-not)). It lives at most `access.PlainSessionIdle` (30 minutes) idle and `access.PlainSessionAbsolute` (12 hours) in all, below the Authenticator's timeouts and the session's own caps ([Sessions](primitives.md#sessions)). Its cookie carries no `Max-Age` and no `Expires`, like every cookie set over plain HTTP, so it ends with the browser ([Session cookie](configuration.md#session-cookie)).

The limiter's device cookie is the one long-lived secret a plain sign-in issues, and it only relaxes the sign-in limiter for the device that holds it. Over plain HTTP it ends with the browser too. A cookie sealed by a plain sign-in never makes a known device, the one a first second factor may be bound from ([Pending sign-ins](configuration.md#pending-sign-ins)), and a plain sign-in re-seals a known device's cookie as plain until its next secure one.

A pending sign-in is bound to its transport as a session is: a ticket a plain step 1 answered finishes only over plain HTTP, and lists only the steps plain HTTP allows, the authenticator-app code for a second factor. A plain step 1 whose next step allows none, an enrolment or a passkey as the only second factor, answers 403 `auth_https_required` and makes no ticket.

## What the screens learn

`Service.State(ctx, c)` takes the request's `Client` and answers what the sign-in screen needs over that transport, so a screen never repeats the table above. `accesshttp` serves it as `authState`'s `StateResponse`:

- `secure` is the request's `Client.Secure`.
- `password_login`, `passkeys` and `oidc` are each offered and admitted over this transport. Over plain HTTP, `passkeys` and `oidc` are false whatever the configuration, and under `PostureSecure` `password_login` is false too.
- `https_required` lists what HTTPS would add, from `password`, `setup`, `passkeys` and `oidc` in that order: only a method the app offers, and `setup` only while setup is still required. It is `[]` on a secure request. An app with no single sign-on never lists `oidc`.
- `plain_session` is set only on a plain request under `PosturePerRequest`: `idle_seconds` and `absolute_seconds` are the limits a session signed in over that request gets: [the plain session's](#the-plain-session), lowered to the Authenticator's own timeouts. `Rules.SessionCaps` can lower a session's limits further, per client, so those are known only after sign-in, from the session's own deadlines.
- `https_origin` is `Rules.HTTPSOrigin` on a plain request when the app set one, so the screen can link to the HTTPS address. It is a link only, and nothing trusts it ([Rules](configuration.md#rules)).

The screen's states follow from those fields:

| State | Cause | Screen |
| --- | --- | --- |
| Secure | `secure` is true | everything the app offers |
| Plain, relaxed | `secure` false, `password_login` true | the password form, one line naming what `https_required` lists, and the shorter session from `plain_session` |
| Needs HTTPS | `secure` false, and `https_required` lists `password` or `password_login` is false | no form, "This app needs HTTPS", and a link to `https_origin` when present. A relaxed app with password sign-in off shows the same state, so `password_login` false alone does not mean `PostureSecure` |
| First setup, plain | `setup_required` and `secure` false | relaxed: the password setup form; strict: "This app needs HTTPS" |

Once signed in, `MeResponse.session.secure` and each `SessionView.secure` carry the session's transport. A plain session's Account and Sessions screens show it as plain HTTP with its end, the earlier of its two deadlines, and show the actions that need HTTPS as disabled. A refusal with `auth_session_expired` and reason `transport_changed` means the session was signed out because the connection changed between HTTP and HTTPS ([What the binding protects](#what-the-binding-protects-and-what-it-does-not)), which the screen shows as a signed-out state, not an error.

## Recent auth and the fresh sign-in

A plain session's recent-auth time is its sign-in, because nothing over plain HTTP refreshes it: every step-up needs HTTPS. Once that time is older than `Rules.RecentAuth`, an action that needs recent auth, such as `authPasswordSet`, answers 403 `auth_recent_auth_required` with `Reason` `sign_in_again`, and the client asks for a fresh sign-in in place of the step-up dialog (`withStepUp`'s `signInAgain` in [`@cplieger/access`](../web/README.md)). A secure session's refusal carries no reason. A key, a custom verifier's principal and the bypass never get `sign_in_again`, since a sign-in cannot help them. A handler of yours that guards its own action gets the same answer from `access.RequireRecentAuth` and `access.ErrorFor` ([Guards](primitives.md#guards)).

A fresh sign-in replaces the session its request presented. `accesshttp` puts the hash of the session cookie it read for the request's transport in `Client.Presented`, and a full sign-in deletes that session before it counts the user's sessions against `Rules.MaxSessionsPerUser`, when the session is the signing-in user's and on the same transport. Its `session_revoked` entry carries `signed_in_again` ([The security log](security-log.md)). The user then holds one session for that browser, a session on another device survives the limit, and a token sniffed from the old session stops working at the sign-in. Another user's session, a session on the other transport and a missing one are left alone. An app that calls `account` directly sets `Client.Presented` the same way, from `CookieConfig.ReadCookie`.

## Keys over plain HTTP

An API key works over plain HTTP under `PosturePerRequest`, because a LAN scraper such as Prometheus often has no TLS. A key is never issued over plain HTTP: `authKeyCreate` and `authKeyRotate` are refused, for a session and for a key alike. Create keys over HTTPS, or out of band with `account.OutOfBand`.

## HTTPS-only routes of your own

A route of yours that mints a secret, or that should never run in clear, sets `HTTPS` on its gate row. The row then refuses a plain request with 403 `auth_https_required` before the handler runs ([Guarding your own routes](gate.md#the-classes)).

## What the binding protects, and what it does not

A session is bound to the transport that created it, and one presented on the other transport is refused and revoked ([Sessions](primitives.md#sessions)). A session token sniffed from a plain request therefore never reaches what an HTTPS session can do: passkeys, OIDC, step-up, keys and invites. A forged `X-Forwarded-Proto` from a peer you do not trust is ignored, so a plain request cannot claim to be secure.

The binding does not protect a password typed over plain HTTP. An observer on that network can read it, and over HTTPS it grants everything the password grants. The control for that is a second factor at sign-in; without one, use plain HTTP only on a network whose observers you trust.
