# Non-goals

These features are left out of access on purpose, and they are not planned. This page gives the reason for each and what to use instead, for a developer checking whether the library fits.

| Feature | Reason and alternative |
| --- | --- |
| A CSRF token | Go's standard library refuses a cross-origin request with any method other than GET, HEAD or OPTIONS, judged from its `Sec-Fetch-Site` and `Origin` headers, with no token. Wrap your handlers in [`http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection) |
| Several processes over one store | Every read-check-write decision runs inside one `Store.Update`, whose serialisability your store guarantees, but the rate limiter's windows and the pending passkey ceremonies live in the process. Run one process per store, as a bbolt or single-file store already requires |
| OIDC token refresh | The library handles sign-in, not long-lived API access. Use an `oauth2.TokenSource` from `golang.org/x/oauth2` |
| A registry of several OIDC providers | `account.Config.OIDC` returns one `oidc.Provider`, so `account` and `accesshttp` sign in through one identity provider. To offer several, put one identity provider in front that brokers the others |
| OIDC back-channel logout | An enterprise single sign-on feature, outside the scope of a library of building blocks |
| The OIDC userinfo endpoint | The ID token's claims are enough to sign a user in |
| WebAuthn metadata-service verification | The ceremony functions own the relying-party configuration. See the note below |
| WebAuthn attestation conveyance | The default `none` is correct for most relying parties, per FIDO Alliance guidance |
| Filtering authenticators by AAGUID | The ceremony functions own the relying-party configuration. See the note below |
| Passkey well-known endpoints | A concern of the browser and the credential manager, not of a server library |
| Role hierarchies and permission sets | `HasRole` checks one flat role. Use [Apache Casbin](https://github.com/apache/casbin) for ACL, RBAC with domains or ABAC, or [Ory Keto](https://github.com/ory/keto) for relationship-based permissions |
| Session cookie encryption and signing | The session cookie holds only a random token whose hash the store keeps, so it carries no sensitive data. The cookies that do carry state, the OIDC flow cookie, the pending-link cookie and the trusted-device cookie, are sealed with an `access.Sealer` |

The library also has no TOTP or SMS second factor. A custom `CredentialVerifier` passed as `Config.Verifier` can add one.

## The two authenticator-policy rows

Metadata-service verification and AAGUID filtering are both policies about which authenticators a deployment accepts. Each is enforceable only where this library is the relying party. A deployment that needs one runs an identity provider. The identity provider then becomes the relying party and applies the policy itself, with nothing needed from this library.

So `webauthn.New` owns the relying-party configuration and offers no way to inject such a policy. An opening there would break the boundary that keeps every go-webauthn type out of the exported API.

The stored credential record already keeps the raw attestation and the AAGUID. AAGUID filtering also needs attestation conveyance to work at all. The AAGUID arrives unaltered only under `direct` or `enterprise` conveyance, and the default `none` removes it.
