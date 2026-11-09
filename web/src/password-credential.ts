// Chromium-only and absent from TypeScript's DOM lib; its instances are plain Credentials,
// which navigator.credentials.store accepts.
// https://w3c.github.io/webappsec-credential-management/#passwordcredential
type PasswordCredentialCtor = new (data: { id: string; password: string }) => Credential;

/**
 * Asks the browser's password manager to save username and password after a form that
 * submits over fetch, where no navigation follows for its own save heuristic to see. Does
 * nothing where PasswordCredential is missing, for an empty username or password, and when
 * the browser declines; never rejects.
 */
export async function storePasswordCredential(username: string, password: string): Promise<void> {
  if (username === "" || password === "") {
    return;
  }
  const g = globalThis as {
    readonly PasswordCredential?: PasswordCredentialCtor;
    readonly navigator?: { readonly credentials?: CredentialsContainer };
  };
  const ctor = g.PasswordCredential;
  const store = g.navigator?.credentials;
  if (typeof ctor !== "function" || store === undefined) {
    return;
  }
  try {
    await store.store(new ctor({ id: username, password }));
  } catch {
    // A declined, blocked or unimplemented store is not the caller's failure.
  }
}
