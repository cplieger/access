import { describe, expect, it } from "vitest";
import { createSessionsModel } from "./sessions.js";
import { fakeServer, refusal } from "./test-helpers/server.js";
import type { Answer } from "./test-helpers/server.js";
import { fixture, isObject } from "./test-helpers/wire.js";
import { forbidStorage } from "./test-helpers/storage.js";

forbidStorage();

function sessions(): Record<string, unknown>[] {
  const current = fixture("SessionView");
  if (!isObject(current)) {
    throw new Error("SessionView.json is not an object");
  }
  const { label: _l, ...other } = current;
  return [current, { ...other, id: "s2", current: false }, { ...other, id: "s3", current: false }];
}
const list: Answer = { status: 200, body: sessions() };
const noContent: Answer = { status: 204 };
const ids = (m: ReturnType<typeof createSessionsModel>): string[] =>
  m.sessions.value.map((s) => s.id);

describe("createSessionsModel", () => {
  it("is empty until refresh, then holds the server's list", async () => {
    const s = fakeServer({ "GET /api/auth/sessions": list });
    const m = createSessionsModel(s.client);
    expect(m.sessions.value).toEqual([]);
    expect(await m.refresh()).toMatchObject({ ok: true, status: 200, data: undefined });
    expect(m.sessions.value).toEqual(sessions());
    expect(s.sent.map((x) => x.route)).toEqual(["GET /api/auth/sessions"]);
  });

  it("keeps the list when a refresh is refused", async () => {
    const answers: Record<string, Answer> = { "GET /api/auth/sessions": list };
    const m = createSessionsModel(fakeServer(answers).client);
    await m.refresh();
    answers["GET /api/auth/sessions"] = refusal(503, "auth_unavailable");
    expect(await m.refresh()).toMatchObject({ ok: false, status: 503, code: "auth_unavailable" });
    expect(ids(m)).toEqual(["s1", "s2", "s3"]);
  });

  it("drops a revoked session once the server accepts", async () => {
    const s = fakeServer({
      "GET /api/auth/sessions": list,
      "DELETE /api/auth/sessions/s2": noContent,
    });
    const m = createSessionsModel(s.client);
    await m.refresh();
    expect((await m.revoke("s2")).ok).toBe(true);
    expect(ids(m)).toEqual(["s1", "s3"]);
    expect(s.sent.map((x) => x.route)).toEqual([
      "GET /api/auth/sessions",
      "DELETE /api/auth/sessions/s2",
    ]);
  });

  it("keeps only the current session after revokeOthers", async () => {
    const s = fakeServer({
      "GET /api/auth/sessions": list,
      "POST /api/auth/sessions/revoke-others": noContent,
    });
    const m = createSessionsModel(s.client);
    await m.refresh();
    expect((await m.revokeOthers()).ok).toBe(true);
    expect(ids(m)).toEqual(["s1"]);
  });

  it("sets and clears a label once the server accepts", async () => {
    const s = fakeServer({
      "GET /api/auth/sessions": list,
      "PUT /api/auth/sessions/s2": noContent,
      "PUT /api/auth/sessions/s1": noContent,
    });
    const m = createSessionsModel(s.client);
    await m.refresh();
    await m.rename("s2", "phone");
    expect(s.sent[1]?.body).toEqual({ name: "phone" });
    expect(m.sessions.value[1]?.label).toBe("phone");
    await m.rename("s1", "");
    expect(s.sent[2]?.body).toEqual({ name: "" });
    expect(m.sessions.value[0] && "label" in m.sessions.value[0]).toBe(false);
    expect(m.sessions.value[2]).toEqual(sessions()[2]);
  });

  it("changes nothing when the server refuses a change", async () => {
    const s = fakeServer({
      "GET /api/auth/sessions": list,
      "DELETE /api/auth/sessions/s2": refusal(404, "auth_not_found"),
      "POST /api/auth/sessions/revoke-others": refusal(403, "auth_recent_auth_required"),
      "PUT /api/auth/sessions/s2": refusal(400, "auth_bad_request", "label_too_long"),
    });
    const m = createSessionsModel(s.client);
    await m.refresh();
    expect(await m.revoke("s2")).toMatchObject({ ok: false, status: 404 });
    expect(await m.revokeOthers()).toMatchObject({ ok: false, status: 403 });
    expect(await m.rename("s2", "x".repeat(200))).toMatchObject({ ok: false, status: 400 });
    expect(m.sessions.value).toEqual(sessions());
  });

  it("offers no way to write the list", () => {
    const m = createSessionsModel(fakeServer({}).client);
    expect(() => {
      (m.sessions as { value: unknown }).value = [];
    }).toThrow(TypeError);
  });
});
