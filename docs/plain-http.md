# Plain HTTP

access can serve a request that crossed a network in clear, such as a LAN address an instance answers without TLS. This page says what such a request may do under each cookie posture, how API keys and your own routes fit in, and what binding a session to its transport protects. Read it before you serve plain HTTP, or before you choose a posture.

A request is plain when the `ClientAddr.Secure` your resolver answers is false, and secure when TLS ended at your server or at a proxy you trust ([Authenticator configuration](configuration.md#authenticator-configuration)). `account` reads the same fact from `Client.Secure` and `Principal.Secure`, so a `Client` or `Principal` you build without `Secure` is plain and is refused where plain requests are.

## The two postures

The posture is `CookieConfig.Posture`, and it is the only switch ([Session cookie](configuration.md#session-cookie) gives each posture's cookie names).

- `PostureSecure`, the default, is HTTPS only. `Authenticate` refuses every plain request with 403 `auth_https_required` ([Session cookie](configuration.md#session-cookie) says where in the chain). Every `account` operation that takes a `Client` refuses a plain one too, sign-in and setup included. `State` and `Logout` are the two exceptions: `State` answers what the sign-in screen needs, and `Logout` only ends a session. Run it when every client reaches the app over HTTPS.
- `PosturePerRequest` serves both. A secure request may do everything, and a plain one gets the policy below. Run it for one instance that serves plain-HTTP LAN clients and HTTPS clients through a proxy.

## What a plain request may do

Under `PosturePerRequest`, a plain request may sign in and set up the first account by password, and use what a password session can use. It gets no other sign-in ceremony, no step-up, no recovery, no removal of the one method a plain session signs in with, and no operation that answers a newly issued long-lived secret.

| Allowed over plain HTTP | Refused over plain HTTP with 403 `auth_https_required` |
| --- | --- |
| `authState`, `authSetupPassword`, `authLoginPassword`, `authLogout` | `authSetupPasskeyBegin`, `authSetupPasskeyFinish`, `authLoginPasskeyBegin`, `authLoginPasskeyFinish` |
| `authMe`, `authProfile`, `authMethodReenable` | every OIDC route: `authOIDCStartSignIn`, `authOIDCStartLink`, `authOIDCStartStepUp`, `authOIDCCallback`, `authOIDCPending`, `authOIDCLinkPending` |
| `authPasswordSet`, whose recent auth is the sign-in's time | `authStepUpPassword`, `authStepUpPasskeyBegin`, `authStepUpPasskeyFinish` |
| `authPasskeys`, `authPasskeyRename`, `authPasskeyRemove`, `authWebAuthnSignals`, `authOIDCUnlink` | `authPasswordRemove` |
| `authSessions`, `authSessionRename`, `authSessionRevoke`, `authSessionsRevokeOthers` | `authPasskeyRegisterBegin`, `authPasskeyRegisterFinish` |
| `authKeys`, `authKeyRename`, `authKeyRevoke`, `authAdminKeys`, `authAdminKeyRevoke` | `authRecoveryStart`, `authRecoveryPassword`, `authRecoveryPasskeyBegin`, `authRecoveryPasskeyFinish` |
| `authAdminUsers`, `authAdminUserCreate`, `authAdminUserUpdate`, `authAdminUserDelete`, `authAdminTokens`, `authAdminSecurityLog` | `authInviteAcceptPassword` |
| every route of yours on the gate, by its class, except a row marked `HTTPS` | `authKeyCreate`, `authKeyRotate`, `authAdminRecovery`, `authAdminInvite` |

Two rows need a reason:

- **Removing the password is refused.** Over plain HTTP the password is the session's only way back in, since every other sign-in method needs HTTPS.
- **Creating a user is allowed.** It answers no secret, and the new user's password is exposed exactly as a password change's is.

`account` enforces the table, so an app that calls it directly gets the same answers: each operation's godoc names its plain answer. An `OutOfBand` actor has no transport and is never refused. An operation that takes both a `Client` and a `Principal` needs both to be secure. In `account` the refusal comes before any other check, limiter charge or store read, so a refused plain request costs nothing and its answer does not depend on its input. `accesshttp` and the gate only translate `access.ErrHTTPSRequired` into the code, and keep no copy of the table.

Each OIDC route is admitted by `account` before it touches a cookie or the identity provider: the sign-in start, the callback and the pending-link read through `Service.AdmitOIDC`, and the link and step-up starts through `Service.AdmitOIDCSession`. A plain start therefore sets no flow cookie and sends the browser nowhere. A plain pending-link read answers 403 even when it presents a valid pending cookie, which it neither reads nor clears.

## Recent auth and the fresh sign-in

A plain session's recent-auth time is its sign-in, because nothing over plain HTTP refreshes it: every step-up needs HTTPS. Once that time is older than `Rules.RecentAuth`, an action that needs recent auth, such as `authPasswordSet`, answers 403 `auth_recent_auth_required` with `Reason` `sign_in_again`, and the client asks for a fresh sign-in in place of the step-up dialog. A secure session's refusal carries no reason. A key, a custom verifier's principal and the bypass never get `sign_in_again`, since a sign-in cannot help them. A handler of yours that guards its own action gets the same answer from `access.RequireRecentAuth` and `access.ErrorFor` ([Guards](primitives.md#guards)).

A fresh sign-in replaces the session its request presented. `accesshttp` puts the hash of the session cookie it read for the request's transport in `Client.Presented`, and a full sign-in deletes that session before it counts the user's sessions against `Rules.MaxSessionsPerUser`, when the session is the signing-in user's and on the same transport. Its `session_revoked` entry carries `signed_in_again` ([The security log](security-log.md)). The user then holds one session for that browser, a session on another device survives the limit, and a token sniffed from the old session stops working at the sign-in. Another user's session, a session on the other transport and a missing one are left alone, and a recovery start replaces nothing. An app that calls `account` directly sets `Client.Presented` the same way, from `CookieConfig.ReadCookie`.

The limiter's device cookie is the one long-lived secret a plain sign-in issues, and it only relaxes the sign-in limiter for the device that holds it. Over plain HTTP it is set, like every cookie there, with no `Max-Age` and no `Expires`, so it ends with the browser ([Session cookie](configuration.md#session-cookie)).

## Keys over plain HTTP

An API key works over plain HTTP under `PosturePerRequest`, because a LAN scraper such as Prometheus often has no TLS. A key is never issued over plain HTTP: `authKeyCreate` and `authKeyRotate` are refused, for a session and for a key alike. Create keys over HTTPS, or out of band with `account.OutOfBand`.

## HTTPS-only routes of your own

A route of yours that mints a secret, or that should never run in clear, sets `HTTPS` on its gate row. The row then refuses a plain request with 403 `auth_https_required` before the handler runs ([Guarding your own routes](gate.md#the-classes)).

## What the binding protects, and what it does not

A session is bound to the transport that created it, and one presented on the other transport is refused and revoked ([Sessions](primitives.md#sessions)). A session token sniffed from a plain request therefore never reaches what an HTTPS session can do: passkeys, OIDC, step-up, recovery, keys and invites. A forged `X-Forwarded-Proto` from a peer you do not trust is ignored, so a plain request cannot claim to be secure.

The binding does not protect a password typed over plain HTTP. An observer on that network can read it, and over HTTPS it grants everything the password grants. The control for that is a second factor at sign-in; without one, use plain HTTP only on a network whose observers you trust.
