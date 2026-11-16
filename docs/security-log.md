# The security log

`account` keeps an append-only log of the security changes it makes: sign-ins, credential and key changes, changes to accounts, and locks. Each entry is appended through the same transaction as the change it records, inside that operation's `Store.Update`, so the change and its entry commit together or not at all. A crash cannot keep one without the other, and an entry still names its actor after that session or key is deleted. Your store keeps the log through the `account.LogStore` role ([Implementing the store](storage.md#the-security-log)).

## What an entry holds

An `account.LogEntry` holds:

- `Event`, the same `account.Event` that `Config.OnEvent` receives: its kind, the account it is about (`UserID`), the actor's IDs, the kind's own fields (method, role, session IDs, key or passkey ID, and for a lock its trust context), and `Seq`, the entry's position in the log.
- `At`, when the entry was appended, from the service clock at millisecond precision. `Event.At` is when the change happened. They come from separate clock reads, so they can differ slightly for any entry. Only for a lock does `Event.At` name an earlier moment, the lock time, as [failed sign-ins](#failed-sign-ins-and-locks) explains.
- `Class`, `change` or `session`, which retention counts separately.
- `ActorLabel`, `ActorUserAgent` and `ActorKeySuffix`: the acting session's label and user agent, or the acting key's label and suffix, read from the store in the same transaction. A sign-in's entries take the session it created. Renaming or deleting that session or key later leaves the entry unchanged.
- `IP`, the client address of the request that made the change. It is zero when the change has no request address: the background sweep, out-of-band calls, `Logout`, which takes only the token hash, the revoke of a session presented on the other transport, an `AppendLog` entry with the zero `Actor`, and a principal your code built rather than `Authenticate`, for an operation that takes no `Client`.
- `Detail`, the text of an app's own entry. A library entry leaves it empty, except two kinds of `session_revoked`, where a session presented on the other transport carries `transport_changed` and a session a fresh sign-in replaced carries `signed_in_again`, and an `owner_set` that `account.New` journalled for an owner holding no password or passkey, which carries `owner_needs_local_method`.

No entry holds a password, token, cookie, key or hash: no field of `LogEntry`, `Event` or `EventActor` has the type `access.Secret` or `access.Hash`. No entry holds a username either. The subject and the actor are user IDs, which a store never reuses, so an entry is never mistaken for a later user's. The label is the one the user gave the session or key, as stored when the change ran, and the user agent is the value the session stored when it was created. Nothing else a caller sends enters a library entry: no name a failed attempt typed and no request header. Client IP addresses are stored, as `Session.LastIP` stores them, and [retention](#retention) bounds how long they stay.

## What is logged

Each operation appends its entries in the order it reports its events to `OnEvent`.

| Kind | Class | Appended by |
| --- | --- | --- |
| `user_created` | change | first-user setup (with the admin role), `CreateUser`, `AcceptInvitePassword`, and an OIDC sign-in, an invite accepted by OIDC or `CreatePendingOIDC` that creates the account, which is linked from the start and gets no `oidc_linked` |
| `signed_in` | session | every full sign-in: password, the second step of a pending password sign-in (with `Method` password), passkey, OIDC (an invite accepted by OIDC included), `CreatePendingOIDC`, `LinkPendingOIDCByAdmin` (with `Method` oidc), first-user setup and `AcceptInvitePassword` |
| `stepped_up` | session | `StepUpPassword`, `StepUpCode`, a passkey step-up and an OIDC step-up |
| `second_factor_failed` | session | the first refused proof of a pending sign-in's second step, a code (`SignInWithCode`), a passkey (`SecondFactorPasskeyFinish`) or a recovery code (`SignInWithRecoveryCode`), with `Method` the factor and, for a code or a recovery code, `Detail` the refusal's reason (`code_invalid`, `code_reused`, `method_locked`). Later refusals on the same ticket add nothing: the failure record counts them. A refusal after a correct password means someone else may hold it |
| `session_revoked` | session | `RevokeSession`, `Logout` when it ended a session, a sign-in that ends sessions past `Rules.MaxSessionsPerUser`, with one entry naming every session it ended, the revoke of a session presented on the other transport, whose `Detail` is `transport_changed` (`account.LogDetailTransportChanged`), and a full sign-in that replaced the session its request presented, in an entry of its own ahead of any `MaxSessionsPerUser` entry, whose `Detail` is `signed_in_again` (`account.LogDetailSignedInAgain`) |
| `user_sessions_revoked` | change | `RevokeOtherSessions`, `SetPassword`, an OIDC link that leaves the user's local methods dormant, `ApplySSO` and `MigrateSSO` for each account whose local sessions the new mode ends, and `SetOwner` removing an owner whose local methods the mode keeps dormant, and `AdminUnlinkOIDC`, `AdminRelinkOIDC`, `SetTemporaryPassword` and `ResetSecondFactor`, which end every session of the user, each when it ended at least one session of the user. A role change, a disable and a delete name the sessions they end in their own entry instead |
| `password_set`, `password_changed` | change | `SetPassword`: `password_set` when the user held no password, `password_changed` when one was replaced |
| `password_removed` | change | `RemovePassword` |
| `totp_added`, `totp_replaced` | change | `FinishTOTP`: `totp_added` when the user held no TOTP, `totp_replaced` when the current code replaced one; `PendingTOTPFinish`'s `totp_added`, by the user in the session it creates |
| `totp_removed` | change | `RemoveTOTP`, `RemovePassword`, which deletes the TOTP the password had, and the enrolment finish of a recovery, which deletes the lost one |
| `recovery_code_issued` | change | a change that adds a password or a second factor and leaves the user with a password, a usable second factor and no recovery code: `FinishTOTP`, `PasskeyRegisterFinish`, `SetPassword`'s first password, and the pending enrolment finishes `PendingTOTPFinish` and `PendingPasskeyFinish` |
| `recovery_code_used` | change | the enrolment finish after `SignInWithRecoveryCode`, which spends the code, deletes the lost TOTP and binds the new factor in one change, by the user in the session it creates. The recovery-code step itself writes only its failure count |
| `recovery_code_replaced` | change | `RegenerateRecoveryCode` |
| `passkey_added` | change | `PasskeyRegisterFinish` and `PendingPasskeyFinish`. The passkey of a first-user setup gets no entry of its own: the setup appends `user_created` and `signed_in` |
| `passkey_removed` | change | `RemovePasskey`, and one per passkey `SetTemporaryPassword` or `AdminRelinkOIDC` deletes under `RevokePasskeys` |
| `oidc_linked`, `oidc_unlinked` | change | `OIDCComplete` finishing a link, `LinkPendingOIDC`, and `LinkPendingOIDCByAdmin`, whose `Event.IssuerUserID` and `Event.KeyID` name the issuer of the temporary password it spent, both zero for one issued out of band; `UnlinkOIDC`, `AdminUnlinkOIDC`, and `AdminRelinkOIDC` before its `temporary_password_set` |
| `oidc_not_admitted` | session | `OIDCComplete` refusing a token `Rules.OIDCAdmission` does not admit, at a sign-in, link, invite acceptance or step-up; `UserID` names the account it was for, zero at an invite acceptance and at the sign-in of an identity no account is linked to |
| `role_synced`, `role_sync_skipped` | change | an OIDC sign-in under `Rules.Provisioning.SyncRole`: `role_synced` with the new `Role` when the claim changed it, `role_sync_skipped` with the kept `Role` when the claim was absent or unreadable |
| `key_minted` | change | `CreateAPIKey` |
| `key_rotated` | change | `RotateAPIKey`, naming the key and its owner. The end of the overlap appends nothing: it happens when a request verifies the new secret, and the key list shows it |
| `key_revoked` | change | one per key: `RevokeAPIKey` and `RevokeAnyAPIKey`, with the keys minted below the revoked key. A `RevokeAnyAPIKey` by `account.OutOfBand(channel)` names that channel in `Event.Actor.OutOfBand`; a disable through `UpdateUser`; `DeleteUser`; `SetTemporaryPassword` and `AdminRelinkOIDC` unless `KeepKeys`; and, only when `Rules.RevokeKeysOnCredentialChange` is set, `SetPassword`. Removing a password and adding or removing a passkey revoke no key |
| `role_changed`, `user_disabled`, `user_enabled` | change | `UpdateUser` |
| `user_deleted` | change | `DeleteUser` |
| `invite_issued` | change | `CreateInvite` |
| `setup_token_issued` | change | `IssueSetupToken` |
| `method_locked` | change | the failure-record sweep reporting a lock, or `ReenableMethod` clearing a lock the sweep has not reported yet, before that change's `method_reenabled` entries |
| `method_reenabled` | change | `ReenableMethod`, one per lock it clears, and a successful password sign-in, `StepUpPassword`, password change through `SetPassword` or `RemovePassword` that clears its own attempt's lock after the sweep reported it |
| `owner_set` | change | `SetOwner` making an owner, and `account.New` marking one, with the out-of-band actor `migration`; an owner `New` marked that holds no password or passkey carries `Detail` `owner_needs_local_method` (`account.LogDetailOwnerNeedsLocalMethod`) |
| `owner_removed` | change | `SetOwner` removing an owner, and `account.New` clearing the flag under a single-user Policy from every account but the one enabled admin, with the actor `migration` |
| `sso_mode_changed` | change | `ApplySSO` and `MigrateSSO`, with `Event.SSOMode` the new mode and `Event.PreviousSSOMode` the old one |
| `second_factor_reset` | change | `ResetSecondFactor`, before the `user_sessions_revoked` entry of the sessions it ended |
| `temporary_password_set` | change | `SetTemporaryPassword` and `AdminRelinkOIDC`, before the `passkey_removed`, `key_revoked` and `user_sessions_revoked` entries of what the issue deleted and ended |
| `temporary_password_used` | session | `PasswordLogin` matching a live temporary password and deleting it: spent into a pending sign-in, or cancelled where its path cannot finish. `LinkPendingOIDCByAdmin` spending one appends `oidc_linked` instead. `Event.Plain` (`plain` on the wire) is set when the secret crossed plain HTTP, so a reader of that network may hold it: an app with a notification channel tells the account's holder |
| `temporary_password_withdrawn` | change | `ApplySSO` and `MigrateSSO` bringing an account's local methods back, and `SetOwner` making an owner, each deleting the account's dormant temporary password; `Event.IssuerUserID` and `Event.KeyID` name its issuer, both zero for one issued out of band |
| your app's kinds | change | `Service.AppendLog` ([App entries](#app-entries)) |

These are left out, each for its reason:

- Reads, such as the user, session and key lists, `SecurityLog` itself and `UsableMethods`. They change nothing.
- Admission checks and accessors such as `AdmitOIDC`, `RequireRecentAuth` and `RequireAdminScope`. None of them writes the store.
- The begin step of a passkey ceremony, which writes only the in-memory pending cache.
- Renaming a passkey or a session, and changing a display name. They change display text only, and an entry keeps the label it was written with.
- Failed sign-in attempts, as the next section explains.
- Expired sessions. The sweep still sends `EventSessionsExpired` to `OnEvent`, with `Seq` 0, and logs nothing: expiry is nobody's act, and each session's deadlines were fixed when it was created.
- The expiry of tokens and passkey ceremonies, which is housekeeping.
- The log's own pruning, which is counted instead ([Retention](#retention)).
- Changes to your `Rules` or `Policy`. `Rules` is a function and `Policy` is your code, so the library sees no change to either. Log such a change yourself with `AppendLog`, in the write that makes it.

## Failed sign-ins and locks

A failed attempt writes no entry. Each attempt's failure count is committed before the password is verified, successful attempts included, so an entry written there would record every success as a failure first, and the log cannot correct an entry. An entry written after verification would be a second write after the change, and would make a failed attempt cost more than a successful one.

What the log records is the lock. The password locks for a name after 100 consecutive failures (`account.FailureCap`), counted separately per trust context: attempts with a valid device cookie for the account, and attempts without one. The entry's `Trusted` field says which context locked. The failure-record sweep then appends `method_locked` in the same transaction that marks the lock reported. It runs in `account.New`, each `CleanupInterval`, and early once `account.MaxUntrustedCounts` password sign-in attempts without a valid device cookie for the account have been counted since its last run. It reports only the locks of a name that is a user's. `Event.At` is the time of the lock and `At` the time of the report, which comes up to one `CleanupInterval` later, plus the time of any sweep that failed and was retried.

A lock that `ReenableMethod` clears before the sweep reports it gets its `method_locked` entry in that clearing change, before the change's `method_reenabled` entries. A password check clears only the lock its own attempt set: each attempt is counted before it is compared, so the attempt that reaches the cap locks the password, and its success then removes that lock. A lock that a successful password check clears before it is reported (a sign-in, a step-up, `SetPassword` or `RemovePassword`) gets no entry, as it gets no event.

To see failed attempts, and bursts that lock nothing, set `accesshttp.Config.Audit`. It reports each refusal with its IP address and reason, and you keep those records as long as you choose.

`gate.Config.Audit` does the same for your own routes. It reports `gate.failure`, a refused credential, and `gate.forbidden`, a principal a route's class refuses, each with its reason ([Guarding your own routes](gate.md#the-audit)). They are request-level kinds, like the auth routes' audit events: neither is written to the security log.

## App entries

`Service.AppendLog(ctx, tx, account.AppEntry{...})` appends your app's own entry inside your own `Store.Update` callback, through that callback's `tx`, so the entry commits and rolls back with your change. Return its error from the callback.

- `Kind` is `<app>.<name>`: lowercase letters, digits and underscores, each segment starting with a letter, at least one dot and at most 64 bytes, such as `myapp.password_login_off`. No library kind has a dot, so an app entry never passes as one of the library's.
- `Method` is optional: empty, or a lowercase token of at most 64 bytes that starts with a letter, one of the `auth` methods or your own.
- `Actor` is `account.As(p)` for a principal, `account.OutOfBand(channel)` for an out-of-band channel, or the zero `Actor` for none. A principal's display data and `Principal.IP` are copied as for the library's entries.
- `Detail` is valid UTF-8 of at most 256 bytes on one line, with no control character, bidi control, or line or paragraph separator.

The library sets `At` from its own clock and the class to `change`, and trims the change class in the same transaction. `AppendLog` sends nothing to `OnEvent`: the commit is your app's, so react after it. It reads no `Rules` value, so an invalid `Rules` never fails your own change.

A refused entry is an `*account.AppEntryError` whose `Reason` is `app_kind`, `app_detail` or `app_method` (`account.AppEntryReasons()`), and nothing is appended. After `Shutdown` it returns `account.ErrServiceClosed`, and a store error matches `access.ErrAuthBackend`. Append only through `AppendLog`: calling `tx.AppendLog` yourself skips the checks and the trim.

## Retention

The log has two classes, counted separately so that sign-in churn never removes an account change:

- `session`: `signed_in`, `stepped_up`, `session_revoked`, `oidc_not_admitted`, `second_factor_failed` and `temporary_password_used`;
- `change`: every other kind, your app's included.

| `account.Config` field | What it sets | Default |
| --- | --- | --- |
| `LogMaxChanges` | The most entries the change class holds | `account.DefaultLogMaxChanges`, 10000 |
| `LogMaxSessions` | The most entries the session class holds | `account.DefaultLogMaxSessions`, 10000 |
| `LogMaxAge` | How long an entry is kept | `account.DefaultLogMaxAge`, 365 days |

- Every logged change trims its class to the cap in the same transaction, removing the class's oldest entries beyond it, so the cap holds at any time.
- The background sweep removes entries older than `LogMaxAge` each `CleanupInterval`, so an entry can stay up to one interval longer, plus the time of any sweep that failed and was retried.
- `account.New` drains a log already past its caps or its age before it returns, so a cap you lowered applies at start and never inside a request.
- A deleted user's entries are kept until the age or the cap removes them, because that user's own `user_deleted` entry is the one an investigation needs.
- Removals by the cap are counted. Each class keeps how many entries its cap has removed, durably and never lowered, and `SecurityLog` returns it as `LogClassStats.Evicted`. Removals by age are the stated retention and are not counted.

## Trust model

No unauthenticated request can append an entry. Every entry needs a verified credential, a valid token or an identity provider's verified claims, or is written by the sweep or by your own code: an out-of-band call or `AppendLog`.

A credential holder can append without bound, and that holder is who the log exists to record: someone with a stolen password or session cookie, or a rogue user of a multi-user app. Creating and revoking keys, registering and removing passkeys, or signing in again and again appends an entry each time, and once a class is at its cap each new entry removes the oldest one. The caps are shared by every user, so this can remove the entries that recorded the intrusion, or other users' history.

The library keeps the bound on the log's size and makes the loss visible: `SecurityLog` returns each class's `Evicted` count with every page, so a reader can see that older history was removed, even though the removed entries are gone. For a longer guaranteed history, raise the caps, or copy the log out of the process, as [Copying the log](#copying-the-log) describes.

## Reading the log

`Service.SecurityLog(ctx, p, account.LogFilter{...})` returns an `account.LogPage`: the matching `Entries` and one `Classes` row per class.

- It admits what `Service.Users` admits: a full session, or an API key with `Config.AdminScope` when that scope is set, of a user whose `Policy` allows `OpListUsers`. Under `RolePolicy` that is an admin, and under `SingleOwnerPolicy` the owner. A refused principal never learns whether its filter was valid.
- Every field set in `LogFilter` must match. `Kinds` takes library and app kinds, and nil is every kind. `UserID` is the account the entry is about, `ActorUserID` and `ActorKeyID` the actor's user and key, and zero matches any.
- Entries come newest first, or oldest first when `OldestFirst` is set. `AfterSeq` and `BeforeSeq` are exclusive bounds and never change the order. To page back, pass the smallest `Seq` of the page as `BeforeSeq`. To catch up, set `OldestFirst` and pass the largest `Seq` you hold as `AfterSeq`, as a page that shows new entries from `OnEvent` does after it reconnects.
- `Limit` is the most entries returned: zero means `account.DefaultLogPage`, 50, and the largest is `account.MaxLogPage`, 500. A filtered page reads the store 500 entries at a time until it holds `Limit` matches or the range ends, so the log's size bounds its cost.
- `Classes` holds one row per `account.LogClasses()` value, in that order, with the class's `Count` and `Evicted`. A class never written reads zero. The rows are not filtered, because a removal by the cap removes entries of every user. They are read after the entries, not in one snapshot, so `Count` can include entries appended in between.
- `SecurityLog` reads outside `Update` and never waits on a commit. Entries never change, so two pages never disagree, and a prune between two reads only ends the range sooner.

An invalid filter is refused before any store read with `account.ErrLogFilterInvalid`, matched by an `*account.LogFilterError` whose `Reason` is one of `account.LogFilterReasons()`:

| Reason | Refused filter |
| --- | --- |
| `log_limit` | `Limit` negative or above 500 |
| `log_range` | a `Seq` bound above 2^53 − 1, or `AfterSeq` and `BeforeSeq` both set with no `Seq` between them |
| `log_kind` | a kind that is neither a library kind nor an app kind |
| `log_id` | a negative user or key ID |

Its other errors are those of the admin lists: `account.ErrRulesInvalid`, `ErrSessionRequired`, `ErrScopeRequired`, `ErrPolicyRefused`, `ErrServiceClosed`, and a store error matching `access.ErrAuthBackend`.

### Copying the log

To keep history past the caps, copy the entries to storage the process cannot rewrite:

1. An empty copy reads `LogFilter{OldestFirst: true, Limit: account.MaxLogPage}`, with no bound, which returns the oldest entries the log still holds.
2. It then reads again with the same filter and `AfterSeq` set to the largest `Seq` it holds, and repeats until a page holds fewer than `Limit` entries, which happens only at the newest entry.
3. Each later run starts at step 2 from the largest `Seq` the copy holds.

Entries never change after they are written, so a copy never needs to read an entry twice. Over HTTP the same reads are `?oldest_first=true&limit=500`, then `?oldest_first=true&limit=500&after=<largest seq>`.

## The HTTP route

`accesshttp` serves the log as `GET {Prefix}/security-log`, the route `authAdminSecurityLog`. It is guarded like the other admin lists: a session, or an API key with `account.Config.AdminScope` when that scope is set.

| Query key | `LogFilter` field |
| --- | --- |
| `user` | `UserID` |
| `actor` | `ActorUserID` |
| `actor_key` | `ActorKeyID` |
| `after` | `AfterSeq` |
| `before` | `BeforeSeq` |
| `limit` | `Limit` |
| `kinds` | `Kinds`, comma-separated |
| `oldest_first` | `OldestFirst`, `true` or absent |

Every key but `kinds` and `oldest_first` is a positive decimal. A zero, negative, malformed or repeated one is answered 400 `auth_bad_request` with the key as its `Reason`. `oldest_first` takes only `true`, and `false`, any other value or a repeated key is refused the same way, with `oldest_first` as its `Reason`. A repeated or malformed `kinds` key is refused the same way, with `kinds` as its `Reason`. An absent or empty `kinds` is every kind, and an empty element, as in `kinds=myapp.x,`, is refused with `log_kind`. An invalid filter is answered 400 `auth_bad_request` with the filter's reason.

The response is a `SecurityLogView`. `entries` is always an array, `[]` for an empty page, and `classes` holds one object per class with `class`, `count` and `evicted`. Each entry has `seq`, `at`, `occurred_at` (`Event.At`), `class`, `kind`, `actor`, and when set `user_id`, `ip`, `session_ids`, `key_id`, `passkey_id`, `issuer_user_id`, `method`, `role`, `trusted` and `detail`; an `sso_mode_changed` entry also has `sso_mode` and `previous_sso_mode`. The `actor` object has `user_id`, `session_id`, `key_id`, `out_of_band`, `label`, `user_agent` and `key_suffix`, each left out when empty. The browser client calls the route as `adminSecurityLog({ user, actor, actorKey, after, before, kinds, limit, oldestFirst })`, with `kinds` an array; it sends `oldest_first` only when `oldestFirst` is `true`.
