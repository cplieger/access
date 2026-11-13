import { existsSync } from "node:fs";
import { playwright } from "@vitest/browser-playwright";
import { chromium } from "playwright";
import { defineConfig } from "vitest/config";

// vitest exits 0 with a project left out, so a missing browser must fail the run rather
// than drop the browser project and pass every gate on the node tests alone.
const browserBinary = chromium.executablePath();
if (!existsSync(browserBinary)) {
  throw new Error(
    `no Playwright Chromium at ${browserBinary}: run npx --no-install playwright install chromium`,
  );
}

// `extends: true` is what makes a project inherit the root `test` block; without it
// every strictness option below is silently dropped for that project.
const projects = [
  {
    extends: true,
    test: {
      name: "node",
      environment: "node",
      include: ["src/**/*.node.test.ts"],
    },
  },
  {
    extends: true,
    test: {
      name: "browser",
      include: ["src/**/*.test.ts"],
      exclude: ["src/**/*.node.test.ts", "node_modules/**"],
      browser: {
        enabled: true,
        headless: true,
        // Chromium caps animation frames at ~60Hz, and throttles them further after
        // about 49 test files in one session; this removes the cap.
        provider: playwright({
          launchOptions: { channel: "chromium", args: ["--disable-frame-rate-limit"] },
        }),
        instances: [{ browser: "chromium" }],
        viewport: { width: 1280, height: 720 },
        screenshotFailures: false,
      },
    },
  },
];

export default defineConfig({
  test: {
    projects,
    setupFiles: ["./src/fc-strict-setup.ts"],
    exclude: ["node_modules/**"],
    isolate: true,
    passWithNoTests: false,
    allowOnly: false,
    globals: false,
    expect: {
      requireAssertions: true,
    },
    clearMocks: true,
    mockReset: true,
    restoreMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,
    bail: process.env["CI"] ? 1 : 0,
    testTimeout: 5000,
    hookTimeout: 10000,
    slowTestThreshold: 300,
    sequence: {
      shuffle: { files: false, tests: false },
      concurrent: false,
      hooks: "stack",
    },
    printConsoleTrace: true,
  },
});
