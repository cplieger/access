import { describe, expect, it, vi } from "vitest";
import { storePasswordCredential } from "./password-credential.js";
import { forbidStorage } from "./test-helpers/storage.js";

forbidStorage();

class FakePasswordCredential {
  constructor(readonly data: { id: string; password: string }) {}
}

describe("storePasswordCredential", () => {
  it("stores a PasswordCredential keyed by the username", async () => {
    vi.stubGlobal("PasswordCredential", FakePasswordCredential);
    const store = vi.spyOn(navigator.credentials, "store").mockResolvedValue(undefined as never);
    await storePasswordCredential("alice", "hunter22");
    expect(store).toHaveBeenCalledOnce();
    const stored = store.mock.calls[0]?.[0];
    expect(stored).toBeInstanceOf(FakePasswordCredential);
    expect((stored as unknown as FakePasswordCredential).data).toEqual({
      id: "alice",
      password: "hunter22",
    });
  });

  it("does nothing for an empty username or password", async () => {
    vi.stubGlobal("PasswordCredential", FakePasswordCredential);
    const store = vi.spyOn(navigator.credentials, "store").mockResolvedValue(undefined as never);
    await storePasswordCredential("", "hunter22");
    await storePasswordCredential("alice", "");
    expect(store).not.toHaveBeenCalled();
  });

  it("does nothing where the browser has no PasswordCredential", async () => {
    vi.stubGlobal("PasswordCredential", undefined);
    const store = vi.spyOn(navigator.credentials, "store").mockResolvedValue(undefined as never);
    await storePasswordCredential("alice", "hunter22");
    expect(store).not.toHaveBeenCalled();
  });

  it("resolves when the browser declines the store", async () => {
    vi.stubGlobal("PasswordCredential", FakePasswordCredential);
    vi.spyOn(navigator.credentials, "store").mockRejectedValue(
      new DOMException("no", "NotAllowedError"),
    );
    await expect(storePasswordCredential("alice", "hunter22")).resolves.toBeUndefined();
  });
});
