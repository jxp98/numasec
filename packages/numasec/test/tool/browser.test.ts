import { describe, expect, test } from "bun:test"
import { Layer, ManagedRuntime } from "effect"
import path from "node:path"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Cyber } from "../../src/core/cyber"
import { Operation } from "../../src/core/operation"
import { Observation } from "../../src/core/observation"
import { loadVault, resolveIdentityValue } from "../../src/core/vault"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { Question } from "../../src/question"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import {
  BrowserTool,
  browserLaunchOptions,
  bringBrowserPageToFront,
  cookieHeaderFromContextCookies,
  inferIdentityHeadersFromStorage,
  isBrowserHeadless,
  persistBrowserObservation,
  persistExportedBrowserIdentity,
} from "../../src/tool/browser"
import { tmpdir } from "../fixture/fixture"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
    Question.layer,
  ),
)

describe("tool/browser", () => {
  test("passive_appsec is a valid action in the public parameters schema", async () => {
    const info = await runtime.runPromise(BrowserTool)
    const tool: any = await runtime.runPromise(info.init())
    expect(() => tool.parameters.parse({ action: "passive_appsec", url: "https://example.com" })).not.toThrow()
  })

  test("pause is a valid action in the public parameters schema", async () => {
    const info = await runtime.runPromise(BrowserTool)
    const tool: any = await runtime.runPromise(info.init())
    expect(() => tool.parameters.parse({ action: "pause", url: "https://example.com/login" })).not.toThrow()
  })

  test("export_identity is a valid action in the public parameters schema", async () => {
    const info = await runtime.runPromise(BrowserTool)
    const tool: any = await runtime.runPromise(info.init())
    expect(() => tool.parameters.parse({ action: "export_identity", key: "browser:example.com" })).not.toThrow()
  })

  test("NUMASEC_BROWSER_HEADLESS=false switches browser to headful mode", () => {
    expect(isBrowserHeadless({})).toBe(true)
    expect(isBrowserHeadless({ NUMASEC_BROWSER_HEADLESS: "false" })).toBe(false)
    expect(isBrowserHeadless({ NUMASEC_BROWSER_HEADLESS: "0" })).toBe(false)
    expect(isBrowserHeadless({ NUMASEC_BROWSER_HEADLESS: "off" })).toBe(false)
    expect(isBrowserHeadless({ NUMASEC_BROWSER_HEADLESS: "true" })).toBe(true)
  })

  test("Linux root 有头模式会自动附加 Chromium 兼容参数", () => {
    expect(
      browserLaunchOptions({
        env: { NUMASEC_BROWSER_HEADLESS: "false" },
        platform: "linux",
        uid: 0,
      }),
    ).toEqual({
      headless: false,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"],
    })
  })

  test("有头模式下会尝试前置浏览器页面", async () => {
    let calls = 0
    const focused = await bringBrowserPageToFront(
      {
        bringToFront: async () => {
          calls += 1
        },
      },
      { NUMASEC_BROWSER_HEADLESS: "false" },
    )

    expect(focused).toBe(true)
    expect(calls).toBe(1)
  })

  test("无头模式下不会尝试前置浏览器页面", async () => {
    let calls = 0
    const focused = await bringBrowserPageToFront(
      {
        bringToFront: async () => {
          calls += 1
        },
      },
      { NUMASEC_BROWSER_HEADLESS: "true" },
    )

    expect(focused).toBe(false)
    expect(calls).toBe(0)
  })

  test("按存储语义提取 Authorization、CSRF 与 API Key", () => {
    const headers = inferIdentityHeadersFromStorage(
      {
        auth: JSON.stringify({ accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb" }),
        csrf: "csrf-123",
      },
      {
        apiKey: "key-123",
      },
    )

    expect(headers.Authorization).toBe("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb")
    expect(headers["X-CSRF-Token"]).toBe("csrf-123")
    expect(headers["X-API-Key"]).toBe("key-123")
  })

  test("按当前 URL 过滤浏览器 Cookie 头", () => {
    const header = cookieHeaderFromContextCookies(
      [
        { name: "session", value: "abc", domain: ".app.example.test" },
        { name: "XSRF-TOKEN", value: "csrf", domain: "app.example.test" },
        { name: "idp_session", value: "skip", domain: "login.example-idp.test" },
      ],
      "https://app.example.test/dashboard",
    )

    expect(header).toBe("session=abc; XSRF-TOKEN=csrf")
  })

  test("导出的浏览器身份会写入 vault 并激活", async () => {
    await using fixture = await tmpdir()
    const prev = process.env.XDG_CONFIG_HOME
    process.env.XDG_CONFIG_HOME = path.join(fixture.path, "xdg")

    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          await Operation.create({
            workspace: fixture.path,
            label: "Browser Identity Export",
            kind: "pentest",
            target: "https://app.example.test",
          })

          await runtime.runPromise(
            persistExportedBrowserIdentity(
              {
                key: "browser:app.example.test",
                value: JSON.stringify({
                  headers: { Authorization: "Bearer token-123", "X-CSRF-Token": "csrf-123" },
                  cookies: "session=abc123",
                  source: "browser.export_identity",
                  page_url: "https://app.example.test/dashboard",
                }),
                currentUrl: "https://app.example.test/dashboard",
                cookieCount: 1,
                localKeys: ["accessToken"],
                sessionKeys: ["csrfToken"],
              },
              {
                sessionID: SessionID.make("ses_test"),
                messageID: MessageID.make(""),
              } as any,
            ),
          )

          const vault = await loadVault()
          expect(vault.active_identity).toBe("browser:app.example.test")
          expect(vault.secrets["browser:app.example.test"]).toBeDefined()

          const resolved = resolveIdentityValue(
            "browser:app.example.test",
            vault.secrets["browser:app.example.test"]!.value,
          )
          expect(resolved.headers?.Authorization).toBe("Bearer token-123")
          expect(resolved.headers?.["X-CSRF-Token"]).toBe("csrf-123")
          expect(resolved.cookies).toBe("session=abc123")
        },
      })
    } finally {
      if (prev === undefined) delete process.env.XDG_CONFIG_HOME
      else process.env.XDG_CONFIG_HOME = prev
    }
  })

  test("passive_appsec persists projected forms and observations under an active operation", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Browser Passive",
          kind: "pentest",
          target: "https://app.example.test",
        })
        await runtime.runPromise(
          persistBrowserObservation(
            { action: "passive_appsec", url: "https://app.example.test/login" } as any,
            {
              title: "Passive AppSec -> Login",
              metadata: {
                url: "https://app.example.test/login",
                findings: 1,
                high: 0,
                medium: 1,
                low: 0,
                request_count: 4,
                script_urls: ["https://app.example.test/app.js"],
                forms: [
                  {
                    action: "https://app.example.test/rest/user/login",
                    method: "post",
                    source: "form",
                    inputs: [{ name: "email", type: "email" }, { name: "password", type: "password" }],
                  },
                ],
              },
              output: JSON.stringify({ findings: [{ id: "missing-security-header" }] }),
            },
            {
              sessionID: SessionID.make("ses_test"),
              messageID: MessageID.make(""),
            } as any,
          ),
        )

        const projected = await Cyber.readProjectedState(fixture.path, op.slug)
        const facts = await Cyber.readProjectedFacts(fixture.path, op.slug)
        const observations = await Observation.listProjected(fixture.path, op.slug)
        expect(projected.summary.http_forms).toBeGreaterThan(0)
        expect(projected.summary.observations_projected).toBeGreaterThan(0)
        expect(
          facts.some(
            (fact) =>
              fact.entity_kind === "http_form" &&
              fact.fact_name === "shape" &&
              (fact.value_json as Record<string, unknown> | null)?.source === "form",
          ),
        ).toBe(true)
        expect(observations.some((item) => item.evidence.length > 0)).toBe(true)
      },
    })
  })
})
