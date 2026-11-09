const buffer = (...b: number[]): ArrayBuffer => new Uint8Array(b).buffer;
const text = (s: string): ArrayBuffer => new TextEncoder().encode(s).buffer;

// Outputs a browser may report unasked; go-webauthn refuses each one the RP did not request.
const unsolicited = { credProps: { rk: true }, prf: { enabled: true }, appid: false };

/**
 * A PublicKeyCredential as navigator.credentials.get resolves it: buffers, no toJSON(), and
 * extension outputs nobody requested.
 */
export function assertionCredential(o: { readonly userHandle?: ArrayBuffer | null } = {}): unknown {
  return {
    id: "Y3JlZA",
    rawId: text("cred"),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: text("{}"),
      authenticatorData: buffer(0),
      signature: buffer(1, 2),
      userHandle: o.userHandle === undefined ? text("handle") : o.userHandle,
    },
    getClientExtensionResults: () => unsolicited,
  };
}

/** assertionCredential's finish body, encoded by hand from the bytes above. */
export const assertionJSON = {
  id: "Y3JlZA",
  rawId: "Y3JlZA",
  type: "public-key",
  authenticatorAttachment: "platform",
  response: {
    authenticatorData: "AA",
    clientDataJSON: "e30",
    signature: "AQI",
    userHandle: "aGFuZGxl",
  },
  clientExtensionResults: {},
};

/**
 * A PublicKeyCredential as navigator.credentials.create resolves it; legacy drops what an engine
 * that predates getTransports and authenticatorAttachment lacks.
 */
export function attestationCredential(o: { readonly legacy?: boolean } = {}): unknown {
  const response = {
    attestationObject: buffer(0xff, 0xef),
    clientDataJSON: text("{}"),
    ...(o.legacy === true ? {} : { getTransports: () => ["internal", "hybrid"] }),
  };
  return {
    id: "Y3JlZA",
    rawId: text("cred"),
    type: "public-key",
    ...(o.legacy === true ? {} : { authenticatorAttachment: "cross-platform" }),
    response,
    getClientExtensionResults: () => unsolicited,
  };
}

/** attestationCredential's finish body when the options requested credProps. */
export const attestationJSON = {
  id: "Y3JlZA",
  rawId: "Y3JlZA",
  type: "public-key",
  authenticatorAttachment: "cross-platform",
  response: { attestationObject: "_-8", clientDataJSON: "e30", transports: ["internal", "hybrid"] },
  clientExtensionResults: { credProps: { rk: true } },
};
