# Identity and single sign-on

This page explains who keeps a way in when your app uses single sign-on (SSO): owners, the SSO mode, linking, admission, role sync, offboarding and an outage. Read it before you turn on SSO for a multi-user app, or before you change how its accounts sign in. [OIDC sign-in](oidc.md) explains the protocol side.

## Owners

An owner is an enabled admin that carries `access.User.Owner`. Owners are the break-glass accounts: they keep their password and passkeys under every SSO mode, so they can sign in while the identity provider is down or misconfigured.

- First setup creates its account as an owner. `account.New` marks one in a store that has users and none, as [Owners](configuration.md#owners) describes.
- `Service.SetOwner` (`authAdminOwner`) adds or removes an owner, from an owner's session within `Rules.RecentAuth` or an out-of-band caller such as an admin socket. A new owner needs a password or passkey it signs in with.
- At least one enabled owner always exists. The last one cannot be demoted, disabled, deleted or have the flag removed (`last_owner`).
- Only an owner or an out-of-band caller may change an owner's account: its role, enabled state, password, temporary password, second factor, link or owner flag, or delete it. Anyone else gets `owner_target`. An owner's role never changes while it is an owner (`owner_role`).
- An account created again after a deletion is never an owner.

Keep two owners, and give at least one of them no SSO link, as Microsoft's [emergency access guidance](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access) advises. An owner still meets `Rules.OIDCAdmission` when it signs in by SSO, so a provider account its admins removed stops working there, and the owner signs in locally instead. An owner with no local method that admission refuses recovers with a temporary password issued out of band at the admin socket ([Second factors and temporary passwords](totp.md#the-temporary-password)).

A single-user app has one account, its owner, and accepts no other SSO identity. Any other identity answers as invalid credentials, with no pending link, so nothing reveals whether the owner exists.

## The SSO mode

The store holds one SSO mode for every account but the owners, so no reload of your settings can change it. `Service.ApplySSO` (`authAdminSSOApply`) changes it, for an owner's secure session within `Rules.RecentAuth` or an out-of-band caller. [The SSO mode](configuration.md#the-sso-mode) lists the operations.

| Mode | A linked account | An account with no link |
| --- | --- | --- |
| `SSOAlongside`, the default | signs in by SSO or with its own password or passkey | signs in locally |
| `SSOForLinked` | signs in only by SSO | signs in locally |
| `SSOOnly` | signs in only by SSO | cannot sign in until an admin links it |

A local method the mode forbids is dormant. It is kept, never deleted, and a looser mode brings it back. A dormant password or passkey fails as a wrong password would, after the same work, so no answer tells an owner's name from anyone else's. A forbidden account cannot add a password, passkey, authenticator app or recovery code (`auth_sso_only`), and steps up by SSO only. `MeResponse.sso_only` tells the Account screen to hide those forms.

Before an owner applies a mode, the settings screen shows `Service.SSOReadiness` (`authAdminSSOReadiness`). It counts the accounts the mode leaves unable to sign in, those that lose or regain their local methods, and the temporary passwords it withdraws. `ApplySSO` ends each session the new mode forbids, in the same change.

`ApplySSO` refuses `SSOOnly` until an owner holds a password or passkey it signs in with, and while `Rules.Registration` is anything but `RegistrationOff`. It refuses every mode but `SSOAlongside` in a single-user app, whose one account is an owner.

API keys stay allowed under every mode. An app that wants none for its users sets `RolePolicy.KeysAdminOnly`.

Under `SSOOnly`, new accounts come only from provisioning or an invite accepted by SSO. Password invites, open registration and a temporary password on the sign-in form are refused for anyone but an owner.

## Linking an account

An identity is linked to at most one account, and an account to at most one identity. The key is the token's issuer and subject, `iss` and `sub`. access never links by email or username, so an email that matches an account links nothing, verified or not.

There are two ways to link an existing account.

- **From a session of that account.** The Account screen's link, or the pending screen's "Link to an existing account" after a local sign-in. Under `SSOForLinked` and `SSOOnly`, the link of an account other than an owner's ends its other local sessions and moves the current one onto SSO, since its local methods are now dormant.
- **With an admin's consent, under `SSOOnly` only.** See below.

A conflict is refused, never merged. An identity linked to another account answers `auth_identity_taken`, and an account already linked answers `auth_already_linked`. access cannot move an app's data between two local accounts, so delete or disable the duplicate yourself.

### Linking with an admin's consent

Under `SSOOnly` an unlinked account other than an owner's has no local session to link from.

1. An admin issues the account a temporary password with `SetTemporaryPassword` (`authAdminTemporaryPassword`).
2. The person signs in at the identity provider and reaches the pending screen.
3. The person chooses "Link to an existing account" and enters the account's name and the temporary password. `LinkPendingOIDCByAdmin` (`authOIDCLinkByAdmin`) links the identity, spends the password and signs in by SSO.

The account's own password never works here, only a live temporary password. Every failure gives one answer, and failures count against the pending identity, so a stranger's guesses never lock the account. The account keeps its dormant password, which a later loosening brings back.

### Unlinking

- A user unlinks from Account under the last-method guard, which counts only local methods the mode allows. A linked account other than an owner's therefore cannot unlink itself under `SSOForLinked` or `SSOOnly`.
- `AdminUnlinkOIDC` (`authAdminOIDCUnlink`) removes a link made by mistake, or one to a provider account that was deleted or given to someone else. It needs no remaining method, and it ends every session of the account. Under `SSOForLinked` the unlinked account signs in with its own methods again, so an admin unlink brings them back for that one account. Under `SSOOnly` it signs in again only through the admin link.
- `AdminRelinkOIDC` (`authAdminOIDCRelink`) unlinks and issues a temporary password in one change, for an identity that changed hands.

## Who may sign in

`Rules.OIDCAdmission` names a claim, such as `groups`, and the values that admit an identity. Every SSO sign-in, link, admin link, invite acceptance and step-up checks it, owners' included, before anything is written. The claim may be a string or an array of strings. Any other shape is refused, including Microsoft Entra's group overage, where `_claim_names` replaces the groups. A refused identity is `account.ErrNotAdmitted`. The callback's redirect carries it as `auth_error=auth_forbidden`, with no reason, so the person gets no pending screen, and the log appends `oidc_not_admitted`. A person removed from the group at the provider is refused at their next SSO sign-in.

### Provisioning and role sync

`Rules.Provisioning` is off by default. With `Enabled`, an admitted identity with no account gets one at its first SSO sign-in, with `Role`. When the name is taken, the pending screen offers "Create a new account" under a name the person picks.

- `RoleClaim` and `AdminValues` make an identity whose claim holds an admin value an admin.
- `SyncRole` applies that mapping again at each SSO sign-in. A sync that changes the role ends every other session of the user in the same write, as an admin's role change does, and its `role_synced` entry names the ended sessions; one that keeps the role ends none. A missing or unreadable claim keeps the role and appends `role_sync_skipped`. An owner's role never changes. While `SyncRole` is on, the provider owns the role: a change in the app holds only until the next sign-in, and `UserMethodsView.role_from_provider` lets the Users screen say so.

Use a claim the provider asserts, such as a group, never a profile field the user can edit at the provider.

An invite accepted by SSO creates the account with the invite's role and needs no provisioning, since the invite is the admin's consent. Under `SyncRole` that role holds until the first sync.

## Offboarding and deletion

Removing a person at the identity provider ends neither their sessions nor their API keys, because back-channel logout is not supported. Disable the account in the app: that blocks every sign-in, SSO included, ends its sessions and deletes its keys. A person removed from the admission group is also refused at their next SSO sign-in, but their sessions live until their idle or absolute limit. For shorter SSO sessions, lower them in `Rules.SessionCaps`, which receives the sign-in method.

Disabling is the revocation. Delete an account only when the person must lose its ID. Deleting removes the link with it, and under provisioning the next SSO sign-in creates a new account with a new ID. Data your app stored under the username or the identity is not cleared by access, and attaches to that new account.

## An identity-provider outage

Owners sign in locally while the provider is down. A provider that is wired but unavailable leaves the mode in force, so every other account waits for it. An owner may loosen the mode to `SSOAlongside`, which brings back every dormant local method, of linked and unlinked accounts alike. Review both kinds of account in `SSOReadiness`'s counts, and disable those that should not come back, before you loosen.

## Turning single sign-on off

Before you remove the provider from your app, apply `SSOAlongside` as an owner, and refuse to clear the provider otherwise. `account.New` refuses to start on a stored mode other than `SSOAlongside` while `Config.OIDC` is unset. Its error names the repair: wire the provider again and apply `SSOAlongside`, or set the stored mode to `SSOAlongside` with the app stopped.
