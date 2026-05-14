import z from "zod"
import { Effect } from "effect"
import path from "path"
import * as Tool from "./tool"
import DESCRIPTION from "./browser.txt"
import { buildPassiveAppSecResult } from "../browser/passive-run"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Observation } from "@/core/observation"
import { Operation } from "@/core/operation"
import { activeIdentity, loadVault, resolveIdentityValue, saveVault } from "@/core/vault"
import { Instance } from "@/project/instance"

import { Question } from "@/question"

const browserHeadfulDisableValues = new Set(["0", "false", "no", "off"])

export function isBrowserHeadless(env: Record<string, string | undefined> = process.env) {
  const value = env.NUMASEC_BROWSER_HEADLESS?.trim().toLowerCase()
  if (!value) return true
  return !browserHeadfulDisableValues.has(value)
}

export function browserLaunchOptions(input: {
  env?: Record<string, string | undefined>
  executablePath?: string
  platform?: NodeJS.Platform
  isBun?: boolean
  uid?: number
}) {
  const base = input.executablePath ? { executablePath: input.executablePath } : {}
  const headless = isBrowserHeadless(input.env)
  const platform = input.platform ?? process.platform
  const isBun = input.isBun ?? typeof globalThis.Bun !== "undefined"
  const uid = input.uid ?? (typeof process.getuid === "function" ? process.getuid() : undefined)

  if (platform === "win32" && isBun) {
    if (!headless) {
      return {
        ...base,
        headless: false,
      }
    }
    return {
      ...base,
      headless: false,
      args: ["--headless=new"],
    }
  }

  if (!headless && platform === "linux" && uid === 0) {
    return {
      ...base,
      headless: false,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"],
    }
  }

  return { ...base, headless }
}

const parameters = z.object({
  action: z
    .enum([
      "navigate",
      "click",
      "fill",
      "screenshot",
      "evaluate",
      "pause",
      "export_identity",
      "get_cookies",
      "dom_snapshot",
      "storage_snapshot",
      "console_log",
      "network_tab",
      "dom_diff",
      "passive_appsec",
    ])
    .describe("Browser action to perform"),
  url: z
    .string()
    .optional()
    .describe("URL to navigate to. When provided for non-navigate actions, the page is loaded first."),
  key: z.string().optional().describe("Identity key used by export_identity action"),
  selector: z.string().optional().describe("CSS selector for click/fill actions"),
  value: z.string().optional().describe("Value for fill action or JS code for evaluate"),
  timeout: z.number().optional().describe("Action timeout in ms (default 30000)"),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe("Headers to inject into browser requests"),
  cookies: z.string().optional().describe("Raw Cookie header to seed the browser session"),
  local_storage: z.record(z.string(), z.string()).optional().describe("localStorage seed"),
  session_storage: z.record(z.string(), z.string()).optional().describe("sessionStorage seed"),
  max_bytes: z
    .number()
    .int()
    .min(1024)
    .max(1048576)
    .optional()
    .describe("Max output bytes for dom_snapshot / console_log / network_tab / passive_appsec"),
  clear: z.boolean().optional().describe("Drain console/network buffer after read"),
})

type Params = z.infer<typeof parameters>

interface ConsoleEntry {
  level: string
  text: string
  ts: number
}
interface NetworkEntry {
  ts: number
  method: string
  url: string
  status?: number
  content_type?: string
  duration_ms?: number
  req_id: string
}

interface Session {
  browser: any
  context: any
  page: any
  console: ConsoleEntry[]
  network: NetworkEntry[]
  lastDom?: string
}

const sessions = new Map<string, Session>()

const EVIDENCE_MAX_OUTPUT = 128_000

function cookieSeed(url: string, raw: string) {
  const base = new URL(url)
  const out: Array<{
    name: string
    value: string
    domain: string
    path: string
    secure: boolean
    httpOnly: boolean
  }> = []
  for (const item of raw.split(";")) {
    const trimmed = item.trim()
    const idx = trimmed.indexOf("=")
    if (idx <= 0) continue
    out.push({
      name: trimmed.slice(0, idx).trim(),
      value: trimmed.slice(idx + 1).trim(),
      domain: base.hostname,
      path: "/",
      secure: base.protocol === "https:",
      httpOnly: false,
    })
  }
  return out
}

async function seedStorage(page: any, params: Params) {
  const local = params.local_storage ?? {}
  const session = params.session_storage ?? {}
  if (Object.keys(local).length === 0 && Object.keys(session).length === 0) return
  await page
    .addInitScript(
      (value: { local: Record<string, string>; session: Record<string, string> }) => {
        for (const k of Object.keys(value.local)) window.localStorage.setItem(k, value.local[k]!)
        for (const k of Object.keys(value.session)) window.sessionStorage.setItem(k, value.session[k]!)
      },
      { local, session },
    )
    .catch(() => undefined)
  const current = page.url()
  if (!current || current.startsWith("about:")) return
  await page
    .evaluate(
      (value: { local: Record<string, string>; session: Record<string, string> }) => {
        for (const k of Object.keys(value.local)) window.localStorage.setItem(k, value.local[k]!)
        for (const k of Object.keys(value.session)) window.sessionStorage.setItem(k, value.session[k]!)
      },
      { local, session },
    )
    .catch(() => undefined)
}

type BrowserStorageSnapshot = {
  local: Record<string, string>
  session: Record<string, string>
}

type BrowserCookieLike = {
  name: string
  value: string
  domain?: string
}

async function readBrowserStorage(page: any): Promise<BrowserStorageSnapshot> {
  return await page
    .evaluate(() => {
      const local: Record<string, string> = {}
      const session: Record<string, string> = {}
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i)
        if (key) local[key] = localStorage.getItem(key) ?? ""
      }
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i)
        if (key) session[key] = sessionStorage.getItem(key) ?? ""
      }
      return { local, session }
    })
    .catch(() => ({ local: {}, session: {} }))
}

function normalizeIdentityField(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "")
}

function looksLikeJwt(value: string) {
  return /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/.test(value.trim())
}

function looksLikeOpaqueToken(value: string) {
  return /^[A-Za-z0-9._~+\-/=]{20,}$/.test(value.trim())
}

function normalizeAuthorizationValue(value: string) {
  const trimmed = value.trim()
  if (!trimmed) return undefined
  if (trimmed.startsWith("Authorization:")) {
    return trimmed.slice("Authorization:".length).trim()
  }
  if (/^[A-Za-z][A-Za-z-]*\s+/.test(trimmed)) return trimmed
  return `Bearer ${trimmed}`
}

function visitIdentityCandidates(value: unknown, path: string[], visit: (candidatePath: string[], candidateValue: string) => void, depth = 0) {
  if (typeof value === "string") {
    visit(path, value)
    const trimmed = value.trim()
    if (!trimmed || depth >= 3 || (!trimmed.startsWith("{") && !trimmed.startsWith("["))) return
    try {
      visitIdentityCandidates(JSON.parse(trimmed), path, visit, depth + 1)
    } catch {}
    return
  }

  if (!value || typeof value !== "object" || depth >= 3) return
  if (Array.isArray(value)) {
    for (const item of value) {
      visitIdentityCandidates(item, path, visit, depth + 1)
    }
    return
  }

  for (const [key, child] of Object.entries(value)) {
    visitIdentityCandidates(child, [...path, key], visit, depth + 1)
  }
}

export function inferIdentityHeadersFromStorage(local: Record<string, string>, session: Record<string, string>) {
  const headers: Record<string, string> = {}

  const assign = (name: string, value: string | undefined, force = false) => {
    if (!value) return
    if (!force && headers[name]) return
    headers[name] = value
  }

  const consider = (path: string[], rawValue: string) => {
    const trimmed = rawValue.trim()
    if (!trimmed) return
    const normalizedPath = path.map(normalizeIdentityField).filter(Boolean)
    const joined = normalizedPath.join(".")
    const last = normalizedPath.at(-1) ?? ""

    if (joined.includes("refreshtoken")) return

    if (last.includes("authorization") || joined.includes("authheader")) {
      assign("Authorization", normalizeAuthorizationValue(trimmed), true)
      return
    }

    if (joined.includes("apikey") || joined.includes("xapikey")) {
      assign("X-API-Key", trimmed)
      return
    }

    if (joined.includes("xsrf")) {
      assign("X-XSRF-TOKEN", trimmed, true)
      return
    }

    if (joined.includes("csrf")) {
      assign("X-CSRF-Token", trimmed, true)
      return
    }

    const authLike =
      joined.includes("accesstoken") ||
      joined.includes("authtoken") ||
      joined.includes("idtoken") ||
      joined.endsWith("jwt") ||
      ((last === "token" || joined.endsWith("session.token") || joined.endsWith("auth.token")) &&
        (looksLikeJwt(trimmed) || looksLikeOpaqueToken(trimmed)))

    if (authLike) {
      assign("Authorization", normalizeAuthorizationValue(trimmed))
    }
  }

  for (const [key, value] of Object.entries(session)) {
    visitIdentityCandidates(value, [key], consider)
  }
  for (const [key, value] of Object.entries(local)) {
    visitIdentityCandidates(value, [key], consider)
  }

  return headers
}

function decodeCookieValue(value: string) {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

export function inferIdentityHeadersFromCookies(cookies: BrowserCookieLike[]) {
  const headers: Record<string, string> = {}

  for (const cookie of cookies) {
    const normalized = normalizeIdentityField(cookie.name)
    if (!headers["X-XSRF-TOKEN"] && normalized === "xsrftoken") {
      headers["X-XSRF-TOKEN"] = decodeCookieValue(cookie.value)
      continue
    }
    if (!headers["X-CSRF-Token"] && (normalized === "csrftoken" || normalized === "csrf")) {
      headers["X-CSRF-Token"] = decodeCookieValue(cookie.value)
    }
  }

  return headers
}

function hostMatchesCookieDomain(host: string, domain?: string) {
  if (!domain) return true
  const normalized = domain.replace(/^\./, "").toLowerCase()
  const target = host.toLowerCase()
  return target === normalized || target.endsWith(`.${normalized}`)
}

export function cookieHeaderFromContextCookies(cookies: BrowserCookieLike[], currentUrl?: string) {
  let selected = cookies.filter((cookie) => Boolean(cookie.name))

  if (currentUrl?.startsWith("http://") || currentUrl?.startsWith("https://")) {
    const host = new URL(currentUrl).hostname
    const scoped = selected.filter((cookie) => hostMatchesCookieDomain(host, cookie.domain))
    if (scoped.length > 0) selected = scoped
  }

  const unique = new Map<string, string>()
  for (const cookie of [...selected].sort((left, right) => left.name.localeCompare(right.name))) {
    unique.set(cookie.name, cookie.value)
  }

  const header = Array.from(unique.entries())
    .map(([name, value]) => `${name}=${value}`)
    .join("; ")

  return header || undefined
}

async function readMetaSecurityHeaders(page: any) {
  return await page
    .evaluate(() => {
      const headers: Record<string, string> = {}
      const metas = Array.from(document.querySelectorAll("meta[name][content]")) as HTMLMetaElement[]
      for (const meta of metas) {
        const name = meta.name.toLowerCase()
        const value = meta.content.trim()
        if (!value) continue
        if (name.includes("xsrf")) headers["X-XSRF-TOKEN"] = value
        if (name.includes("csrf")) headers["X-CSRF-Token"] = value
      }
      return headers
    })
    .catch(() => ({} as Record<string, string>))
}

function defaultBrowserIdentityKey(currentUrl?: string) {
  if (currentUrl?.startsWith("http://") || currentUrl?.startsWith("https://")) {
    const target = new URL(currentUrl)
    return `browser:${target.host}`
  }
  return "browser:session"
}

async function exportBrowserIdentityState(params: Params, sessionID: string) {
  const timeout = params.timeout ?? 30_000
  const session = await ensure(sessionID)
  await hydrate(session.context, session.page, params)
  const page = session.page
  const context = session.context

  if (params.url) {
    await page.goto(params.url, { timeout, waitUntil: "domcontentloaded" }).catch(() => undefined)
  }

  const currentUrl = page.url() || params.url
  const storage = await readBrowserStorage(page)
  const contextCookies = await context.cookies()
  const cookies = cookieHeaderFromContextCookies(contextCookies, currentUrl)
  const headers = {
    ...inferIdentityHeadersFromStorage(storage.local, storage.session),
    ...inferIdentityHeadersFromCookies(contextCookies),
    ...(await readMetaSecurityHeaders(page)),
  }

  if (!cookies && Object.keys(headers).length === 0) {
    throw new Error(
      "No reusable browser identity state found. Complete login first, then inspect get_cookies or storage_snapshot if needed.",
    )
  }

  const key = params.key?.trim() || defaultBrowserIdentityKey(currentUrl)
  const value = JSON.stringify({
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    cookies,
    source: "browser.export_identity",
    page_url: currentUrl,
    origin:
      currentUrl && (currentUrl.startsWith("http://") || currentUrl.startsWith("https://"))
        ? new URL(currentUrl).origin
        : undefined,
    exported_at: new Date().toISOString(),
  })
  const resolved = resolveIdentityValue(key, value)

  return {
    key,
    value,
    currentUrl,
    mode: resolved.mode,
    headerKeys: Object.keys(resolved.headers ?? {}),
    hasCookies: Boolean(resolved.cookies),
    cookieCount: cookies ? cookies.split(/;\s*/).filter(Boolean).length : 0,
    localKeys: Object.keys(storage.local).sort(),
    sessionKeys: Object.keys(storage.session).sort(),
  }
}

async function ensure(sessionID: string): Promise<Session> {
  const id = sessionID
  const existing = sessions.get(id)
  if (existing) return existing

  let pw: typeof import("playwright") | undefined
  try {
    pw = await import("playwright")
  } catch {
    // import entirely failed — not installed
  }

  if (!pw?.chromium?.launch) {
    try {
      const { createRequire } = await import("module")
      const require = createRequire(path.join(Instance.directory, "package.json"))
      pw = require("playwright") as typeof import("playwright")
    } catch {
      // local filesystem fallback also failed
    }
  }

  if (!pw?.chromium?.launch) {
    throw new Error("Playwright is not installed. Run: bun add playwright && npx playwright install chromium")
  }

  let firstError: string | undefined
  let browser: Awaited<ReturnType<typeof pw.chromium.launch>>
  try {
    browser = await pw.chromium.launch(browserLaunchOptions({}))
  } catch (err) {
    firstError = err instanceof Error ? err.message : String(err)

    const envPath = process.env.NUMASEC_CHROMIUM_PATH
    if (envPath) {
      try {
        browser = await pw.chromium.launch(browserLaunchOptions({ executablePath: envPath }))
      } catch {
        // Fallback to system PATH below
      }
    }

    if (!browser!) {
      const systemNames = ["chromium", "chromium-browser", "google-chrome", "chrome"]
      for (const name of systemNames) {
        const found = Bun.which(name)
        if (!found) continue
        try {
          browser = await pw.chromium.launch(browserLaunchOptions({ executablePath: found }))
          break
        } catch {
          // try next
        }
      }
    }

    if (!browser!) {
      const pathNote = envPath ? ` | tried NUMASEC_CHROMIUM_PATH=${envPath}` : ""
      throw new Error(
        `Chromium browser not found. Run: npx playwright install chromium — ${firstError}${pathNote}`,
      )
    }
  }

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
  })
  const page = await context.newPage()
  const entry: Session = { browser, context, page, console: [], network: [] }

  const MAX_BUFFER = 500
  page.on("console", (msg: any) => {
    entry.console.push({
      level: msg.type?.() ?? "log",
      text: msg.text?.() ?? String(msg),
      ts: Date.now(),
    })
    if (entry.console.length > MAX_BUFFER) entry.console.shift()
  })
  page.on("pageerror", (err: any) => {
    entry.console.push({ level: "pageerror", text: String(err?.message ?? err), ts: Date.now() })
    if (entry.console.length > MAX_BUFFER) entry.console.shift()
  })
  const pending = new Map<string, { ts: number; method: string; url: string }>()
  context.on("request", (req: any) => {
    const id = `${Date.now()}-${req.url()}`
    pending.set(req, { ts: Date.now(), method: req.method(), url: req.url() })
    ;(req as any).__id = id
  })
  context.on("response", async (resp: any) => {
    const req = resp.request()
    const start = pending.get(req)
    pending.delete(req)
    const ts = start?.ts ?? Date.now()
    const headers = resp.headers?.() ?? {}
    entry.network.push({
      ts,
      method: req.method(),
      url: req.url(),
      status: resp.status(),
      content_type: headers["content-type"],
      duration_ms: Date.now() - ts,
      req_id: (req as any).__id ?? "",
    })
    if (entry.network.length > MAX_BUFFER) entry.network.shift()
  })

  sessions.set(id, entry)

  return entry
}

async function hydrate(context: any, page: any, params: Params) {
  const identity = await activeIdentity().catch(() => undefined)
  const headers = { ...(identity?.headers ?? {}), ...(params.headers ?? {}) }
  if (Object.keys(headers).length > 0) {
    await context.setExtraHTTPHeaders(headers)
  }
  await seedStorage(page, params)
  const url = params.url || page.url()
  const cookieHeader = params.cookies ?? identity?.cookies
  if (cookieHeader && url && url.startsWith("http")) {
    const seed = cookieSeed(url, cookieHeader)
    if (seed.length > 0) await context.addCookies(seed)
  }
  return identity
}

export function persistExportedBrowserIdentity(
  input: {
    key: string
    value: string
    currentUrl?: string
    cookieCount: number
    localKeys: string[]
    sessionKeys: string[]
  },
  ctx: Tool.Context,
) {
  return Effect.gen(function* () {
    const vault = yield* Effect.promise(() => loadVault())
    const previous = vault.active_identity
    const now = new Date().toISOString()

    vault.secrets[input.key] = { value: input.value, updated_at: now }
    vault.active_identity = input.key
    vault.active_identity_set_at = now
    yield* Effect.promise(() => saveVault(vault))

    const resolved = resolveIdentityValue(input.key, input.value)
    const descriptor = {
      mode: resolved.mode,
      header_keys: Object.keys(resolved.headers ?? {}),
      has_cookies: Boolean(resolved.cookies),
    }

    const eventID = yield* Cyber.appendLedger({
      kind: "fact.observed",
      source: "browser",
      summary: `exported browser identity ${input.key}`,
      session_id: ctx.sessionID,
      message_id: ctx.messageID,
      data: {
        action: "export_identity",
        key: input.key,
        previous,
        url: input.currentUrl,
        mode: descriptor.mode,
        header_keys: descriptor.header_keys,
        has_cookies: descriptor.has_cookies,
        cookie_count: input.cookieCount,
        local_keys: input.localKeys,
        session_keys: input.sessionKeys,
      },
    }).pipe(Effect.catch(() => Effect.succeed("")))

    if (previous && previous !== input.key) {
      yield* Cyber.upsertFact({
        entity_kind: "identity",
        entity_key: previous,
        fact_name: "active",
        value_json: false,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      }).pipe(Effect.catch(() => Effect.succeed("")))
    }

    yield* Cyber.upsertFact({
      entity_kind: "identity",
      entity_key: input.key,
      fact_name: "descriptor",
      value_json: descriptor,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))

    yield* Cyber.upsertFact({
      entity_kind: "identity",
      entity_key: input.key,
      fact_name: "active",
      value_json: true,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))

    const slug = yield* Effect.promise(() => Operation.activeSlug(Instance.directory).catch(() => undefined)).pipe(
      Effect.catch(() => Effect.succeed(undefined)),
    )

    if (slug) {
      yield* Cyber.upsertRelation({
        operation_slug: slug,
        src_kind: "operation",
        src_key: slug,
        relation: "uses_identity",
        dst_kind: "identity",
        dst_key: input.key,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      }).pipe(Effect.catch(() => Effect.succeed("")))
    }

    return { previous, descriptor }
  })
}

async function navigateForPassiveAnalysis(page: any, url: string, timeout: number) {
  const response = await page.goto(url, { timeout, waitUntil: "domcontentloaded" })
  const settleTimeout = Math.min(timeout, 5_000)
  await page.waitForLoadState("load", { timeout: settleTimeout }).catch(() => undefined)
  await page.waitForLoadState("networkidle", { timeout: settleTimeout }).catch(() => undefined)
  return response
}

function browserEvidenceMime(action: Params["action"]) {
  if (action === "screenshot") return "image/png"
  if (action === "dom_snapshot") return "text/html"
  return "application/json"
}

function browserEvidenceExt(action: Params["action"]) {
  if (action === "screenshot") return "png"
  if (action === "dom_snapshot") return "html"
  return "json"
}

function summarizePassiveFindings(output: string) {
  try {
    const parsed = JSON.parse(output) as {
      findings?: Array<{ id: string; severity: string; title: string; evidence?: string[] }>
      summary?: { total_findings?: number; request_count?: number }
    }
    return parsed
  } catch {
    return undefined
  }
}

function routeOf(url: string) {
  const target = new URL(url)
  return {
    host: target.hostname,
    origin: target.origin,
    service: `${target.hostname}:${target.port || (target.protocol === "https:" ? "443" : "80")}`,
    route: `${target.origin}${target.pathname || "/"}`,
    scheme: target.protocol.replace(":", ""),
  }
}

function browserEvidencePayload(params: Params, result: Tool.ExecuteResult) {
  return JSON.stringify(
    {
      action: params.action,
      input: {
        url: params.url,
        selector: params.selector,
        timeout: params.timeout,
        headers: params.headers,
        cookies: params.cookies,
      },
      result: {
        title: result.title,
        metadata: result.metadata,
        output: result.output.slice(0, EVIDENCE_MAX_OUTPUT),
        output_truncated: result.output.length > EVIDENCE_MAX_OUTPUT,
      },
    },
    null,
    2,
  )
}

function browserObservationDraft(params: Params, result: Tool.ExecuteResult, currentUrl?: string) {
  if (params.action !== "passive_appsec" && params.action !== "dom_snapshot") return
    const metadata = (result.metadata ?? {}) as Record<string, unknown>
    if (params.action === "passive_appsec") {
      const findings = Number(metadata.findings ?? 0)
      const high = Number(metadata.high ?? 0)
      const medium = Number(metadata.medium ?? 0)
      const requestCount = Number(metadata.request_count ?? 0)
      const forms = Array.isArray(metadata.forms) ? metadata.forms.length : 0
      const scripts = Array.isArray(metadata.script_urls) ? metadata.script_urls.length : 0
      const subtype: "risk" | "intel-fact" = findings > 0 ? "risk" : "intel-fact"
      const severity: "medium" | "info" = high > 0 || medium > 0 ? "medium" : "info"
      return {
        subtype,
        title: `Passive browser AppSec completed for ${currentUrl ?? "target"}`,
        severity,
        confidence: findings > 0 ? 0.6 : 0.5,
        note: `${requestCount} requests, ${forms} input surfaces, ${scripts} scripts, ${findings} candidate signals.`,
        tags: ["browser", "passive-appsec", "web"],
    }
  }
  const summary = metadata.summary as { forms?: unknown[]; links?: unknown[]; scripts?: unknown[] } | undefined
  const forms = Array.isArray(summary?.forms) ? summary.forms.length : 0
  const links = Array.isArray(summary?.links) ? summary.links.length : 0
  const scripts = Array.isArray(summary?.scripts) ? summary.scripts.length : 0
  return {
    subtype: "intel-fact" as const,
    title: `DOM snapshot captured for ${currentUrl ?? "target"}`,
    severity: "info" as const,
    confidence: 0.5,
    note: `${forms} forms, ${links} links, ${scripts} scripts observed in the DOM snapshot.`,
    tags: ["browser", "dom", "web"],
  }
}

export function persistBrowserObservation(params: Params, result: Tool.ExecuteResult, ctx: Tool.Context) {
  return Effect.gen(function* () {
    const currentUrl =
      typeof result.metadata?.url === "string"
        ? result.metadata.url
        : typeof result.metadata?.currentUrl === "string"
          ? result.metadata.currentUrl
          : params.url
    const workspace = Instance.directory
    const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
    const evidence =
      !slug
        ? undefined
        : yield* Effect.promise(() =>
            Evidence.put(workspace, slug, browserEvidencePayload(params, result), {
              mime: browserEvidenceMime(params.action),
              ext: browserEvidenceExt(params.action),
              label: `browser ${params.action}${currentUrl ? ` ${currentUrl}` : ""}`,
              source: "browser",
            }),
          )
    const evidenceRefs = evidence ? [evidence.sha256] : undefined
    const eventID = yield* Cyber.appendLedger({
      kind: "fact.observed",
      source: "browser",
      summary: result.title,
      session_id: ctx.sessionID,
      message_id: ctx.messageID,
      evidence_refs: evidenceRefs,
      data: {
        action: params.action,
        url: currentUrl,
        metadata: result.metadata,
      },
    }).pipe(Effect.catch(() => Effect.succeed("")))

    if (!currentUrl || (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://"))) return

    const route = routeOf(currentUrl)
    yield* Cyber.upsertFact({
      entity_kind: "host",
      entity_key: route.host,
      fact_name: "browser_seen_url",
      value_json: currentUrl,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertFact({
      entity_kind: "service",
      entity_key: route.service,
      fact_name: "transport",
      value_json: route.scheme,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertFact({
      entity_kind: "http_route",
      entity_key: route.route,
      fact_name: `browser_action:${params.action}`,
      value_json: {
        title: result.title,
        metadata: result.metadata,
      },
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertRelation({
      src_kind: "host",
      src_key: route.host,
      relation: "exposes",
      dst_kind: "service",
      dst_key: route.service,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertRelation({
      src_kind: "service",
      src_key: route.service,
      relation: "serves",
      dst_kind: "http_route",
      dst_key: route.route,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    if (typeof result.metadata?.activeIdentity === "string") {
      yield* Cyber.upsertRelation({
        src_kind: "identity",
        src_key: result.metadata.activeIdentity,
        relation: "used_on",
        dst_kind: "http_route",
        dst_key: route.route,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
        evidence_refs: evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed("")))
    }

    if (params.action === "dom_snapshot") {
      const summary = result.metadata?.summary as
        | { forms?: unknown[]; links?: string[]; scripts?: string[] }
        | undefined
      for (const link of summary?.links ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "http_route",
          entity_key: link,
          fact_name: "dom_link",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const script of summary?.scripts ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "artifact",
          entity_key: script,
          fact_name: "javascript_resource",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const form of summary?.forms ?? []) {
        const item = form as { action?: string; method?: string; inputs?: unknown[] }
        if (!item.action || !item.method) continue
        yield* Cyber.upsertFact({
          entity_kind: "http_form",
          entity_key: `${item.method}:${item.action}`,
          fact_name: "shape",
          value_json: item,
          writer_kind: "parser",
          status: "observed",
          confidence: 850,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
    }

    if (params.action === "passive_appsec") {
      const parsed = summarizePassiveFindings(result.output)
      for (const item of (result.metadata?.request_urls as string[] | undefined) ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "http_route",
          entity_key: item,
          fact_name: "browser_request",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 850,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const item of (result.metadata?.form_actions as string[] | undefined) ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "http_form",
          entity_key: item,
          fact_name: "passive_form_action",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const form of (result.metadata?.forms as Array<{
        action?: string
        method?: string
        source?: string
        inputs?: unknown[]
      }> | undefined) ?? []) {
        if (!form.action || !form.method) continue
        yield* Cyber.upsertFact({
          entity_kind: "http_form",
          entity_key: `${form.method}:${form.action}:${form.source ?? "form"}`,
          fact_name: "shape",
          value_json: {
            action: form.action,
            method: form.method,
            source: form.source ?? "form",
            inputs: Array.isArray(form.inputs) ? form.inputs : [],
          },
          writer_kind: "parser",
          status: "observed",
          confidence: 850,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const item of (result.metadata?.script_urls as string[] | undefined) ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "artifact",
          entity_key: item,
          fact_name: "javascript_resource",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const finding of parsed?.findings ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "finding_candidate",
          entity_key: `${route.host}:${finding.id}`,
          fact_name: "passive_appsec",
          value_json: finding,
          writer_kind: "parser",
          status: "candidate",
          confidence: finding.severity === "high" ? 800 : finding.severity === "medium" ? 700 : 600,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
    }

    const observation = browserObservationDraft(params, result, currentUrl)
    if (slug && evidence && observation) {
      const obs = yield* Effect.promise(() => Observation.add(workspace, slug, observation))
      yield* Effect.promise(() => Observation.linkEvidence(workspace, slug, obs.id, evidence.sha256))
    }
  })
}

async function run(params: Params, sessionID: string): Promise<Tool.ExecuteResult> {
  const timeout = params.timeout ?? 30_000
  const session = await ensure(sessionID)
  const identity = await hydrate(session.context, session.page, params)
  const page = session.page
  const context = session.context

  if (params.url && params.action !== "navigate" && params.action !== "passive_appsec") {
    await page.goto(params.url, { timeout, waitUntil: "domcontentloaded" })
  }

  if (params.action === "navigate") {
    if (!params.url) throw new Error("url is required for navigate action")
    const response = await page
      .goto(params.url, { timeout, waitUntil: "networkidle" })
      .catch(() => page.goto(params.url!, { timeout, waitUntil: "domcontentloaded" }))
    const title = await page.title().catch(() => "")
    const content = await page.content()
    const cookies = await context.cookies()
    const preview =
      content.length > 8000
        ? content.slice(0, 8000) + `\n... (truncated, ${content.length} chars total)`
        : content
    return {
      title: `Navigate → ${params.url}`,
      metadata: {
        status: response ? response.status() : undefined,
        pageTitle: title,
        cookieCount: cookies.length,
        url: page.url(),
        activeIdentity: identity?.key,
      },
      output: [
        `Status: ${response ? response.status() : "unknown"}`,
        `Title: ${title}`,
        `URL: ${page.url()}`,
        `Cookies: ${cookies.length}`,
        "",
        "── Page HTML ──",
        preview,
      ].join("\n"),
    }
  }

  if (params.action === "passive_appsec") {
    if (!params.url) throw new Error("url is required for passive_appsec action")
    const networkStart = session.network.length
    const consoleStart = session.console.length
    const response = await navigateForPassiveAnalysis(page, params.url, timeout)
    const title = (await page.title().catch(() => "")) || page.url() || params.url
    const headers = response ? await response.headers() : undefined
    return buildPassiveAppSecResult({
      title,
      headers,
      page,
      context,
      session,
      startIndexes: {
        network: networkStart,
        console: consoleStart,
      },
      max_bytes: params.max_bytes,
      clear: params.clear,
    })
  }

  if (params.action === "click") {
    if (!params.selector) throw new Error("selector is required for click action")
    await page.click(params.selector, { timeout })
    await page.waitForLoadState("networkidle").catch(() => undefined)
    return {
      title: `Click ${params.selector}`,
      metadata: { currentUrl: page.url(), activeIdentity: identity?.key },
      output: `Clicked "${params.selector}". Current URL: ${page.url()}`,
    }
  }

  if (params.action === "fill") {
    if (!params.selector) throw new Error("selector is required for fill action")
    if (!params.value) throw new Error("value is required for fill action")
    await page.fill(params.selector, params.value, { timeout })
    return {
      title: `Fill ${params.selector}`,
      metadata: { currentUrl: page.url(), activeIdentity: identity?.key },
      output: `Filled "${params.selector}" with value.`,
    }
  }

  if (params.action === "screenshot") {
    const buf = await page.screenshot({ fullPage: true, type: "png" })
    const base64 = buf.toString("base64")
    return {
      title: "Screenshot captured",
      metadata: { size: buf.length, url: page.url(), activeIdentity: identity?.key },
      output: "Screenshot captured successfully.",
      attachments: [{ type: "file" as const, mime: "image/png", url: `data:image/png;base64,${base64}` }],
    }
  }

  if (params.action === "evaluate") {
    if (!params.value) throw new Error("value (JS code) is required for evaluate action")
    const result = await page.evaluate(params.value)
    const formatted = typeof result === "string" ? result : JSON.stringify(result, null, 2)
    return {
      title: "JS Evaluate",
      metadata: { currentUrl: page.url(), activeIdentity: identity?.key },
      output: formatted,
    }
  }

  if (params.action === "pause") {
    const cookies = await context.cookies()
    return {
      title: "Browser paused for manual step",
      metadata: {
        currentUrl: page.url(),
        cookieCount: cookies.length,
        activeIdentity: identity?.key,
      },
      output: [
        `Current URL: ${page.url() || params.url || "(blank page)"}`,
        `Cookies: ${cookies.length}`,
        "Complete the manual browser step now (for example login, SSO, MFA, or a challenge).",
        "Choose Continue in numasec when you are ready to resume automated testing.",
        "After resuming, use storage_snapshot or get_cookies to inspect the resulting login state.",
      ].join("\n"),
    }
  }

  if (params.action === "get_cookies") {
    const cookies = await context.cookies()
    const lines = cookies.map(
      (c: any) =>
        `${c.name}=${c.value} (domain=${c.domain}, path=${c.path}, secure=${c.secure}, httpOnly=${c.httpOnly}, sameSite=${c.sameSite})`,
    )
    return {
      title: `${cookies.length} cookies`,
      metadata: { count: cookies.length, url: page.url(), activeIdentity: identity?.key },
      output: lines.join("\n") || "No cookies.",
    }
  }

  if (params.action === "dom_snapshot") {
    const max = params.max_bytes ?? 65536
    const html = await page.content()
    session.lastDom = html
    const title = await page.title().catch(() => "")
    const summary = await page
      .evaluate(() => {
        const forms = Array.from(document.querySelectorAll("form")).map((f) => ({
          action: (f as HTMLFormElement).action,
          method: (f as HTMLFormElement).method,
          inputs: Array.from(f.querySelectorAll("input,textarea,select")).map((i) => ({
            name: (i as HTMLInputElement).name,
            type: (i as HTMLInputElement).type,
          })),
        }))
        const links = Array.from(document.querySelectorAll("a[href]"))
          .slice(0, 200)
          .map((a) => (a as HTMLAnchorElement).href)
        const scripts = Array.from(document.querySelectorAll("script[src]"))
          .map((s) => (s as HTMLScriptElement).src)
          .slice(0, 100)
        return { forms, links, scripts }
      })
      .catch(() => ({ forms: [], links: [], scripts: [] }))
    const body = html.length > max ? html.slice(0, max) + `\n... (truncated, ${html.length} chars)` : html
    return {
      title: `DOM snapshot ${page.url()}`,
      metadata: { url: page.url(), size: html.length, title, summary, activeIdentity: identity?.key } as any,
      output: [
        `URL: ${page.url()}`,
        `Title: ${title}`,
        `Forms: ${summary.forms.length}  Links: ${summary.links.length}  Scripts: ${summary.scripts.length}`,
        "",
        "── Summary ──",
        JSON.stringify(summary, null, 2),
        "",
        "── HTML ──",
        body,
      ].join("\n"),
    }
  }

  if (params.action === "storage_snapshot") {
    const storage = await readBrowserStorage(page)
    const cookies = await context.cookies()
    return {
      title: `Storage ${page.url()}`,
      metadata: {
        localKeys: Object.keys(storage.local).length,
        sessionKeys: Object.keys(storage.session).length,
        cookieCount: cookies.length,
        url: page.url(),
        activeIdentity: identity?.key,
      },
      output: JSON.stringify({ ...storage, cookies }, null, 2),
    }
  }

  if (params.action === "console_log") {
    const max = params.max_bytes ?? 65536
    const entries = [...session.console]
    if (params.clear) session.console.length = 0
    const lines = entries.map((e) => `[${new Date(e.ts).toISOString()}] ${e.level}: ${e.text}`).join("\n")
    const body = lines.length > max ? lines.slice(0, max) + `\n... (truncated, ${lines.length} chars)` : lines
    return {
      title: `Console log (${entries.length})`,
      metadata: { count: entries.length, url: page.url(), activeIdentity: identity?.key },
      output: body || "(no console entries)",
    }
  }

  if (params.action === "network_tab") {
    const max = params.max_bytes ?? 65536
    const entries = [...session.network]
    if (params.clear) session.network.length = 0
    const lines = entries
      .map(
        (e) =>
          `[${new Date(e.ts).toISOString()}] ${e.method} ${e.status ?? "---"} ${e.url}  (${e.duration_ms ?? "?"}ms, ${e.content_type ?? "?"})`,
      )
      .join("\n")
    const body = lines.length > max ? lines.slice(0, max) + `\n... (truncated, ${lines.length} chars)` : lines
    return {
      title: `Network (${entries.length} requests)`,
      metadata: { count: entries.length, url: page.url(), activeIdentity: identity?.key },
      output: body || "(no requests)",
    }
  }

  if (params.action === "dom_diff") {
    const prev = session.lastDom
    if (!prev) throw new Error("dom_diff requires a prior dom_snapshot in this session")
    const current = await page.content()
    session.lastDom = current
    const prevLines = prev.split("\n")
    const curLines = current.split("\n")
    const added: string[] = []
    const removed: string[] = []
    const prevSet = new Set(prevLines)
    const curSet = new Set(curLines)
    for (const l of curLines) if (!prevSet.has(l)) added.push(l)
    for (const l of prevLines) if (!curSet.has(l)) removed.push(l)
    const max = params.max_bytes ?? 65536
    const out = [
      `+ ${added.length} added lines`,
      `- ${removed.length} removed lines`,
      "",
      ...added.slice(0, 200).map((l) => `+ ${l}`),
      ...removed.slice(0, 200).map((l) => `- ${l}`),
    ].join("\n")
    return {
      title: `DOM diff (+${added.length}/-${removed.length})`,
      metadata: { added: added.length, removed: removed.length, url: page.url(), activeIdentity: identity?.key } as any,
      output: out.length > max ? out.slice(0, max) + "\n... (truncated)" : out,
    }
  }

  throw new Error(`Unknown action: ${params.action}`)
}

export const BrowserTool = Tool.define<typeof parameters, Record<string, any>, Question.Service>(
  "browser",
  Effect.gen(function* () {
    const question = yield* Question.Service

    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context) =>
        Effect.gen(function* () {
          if (params.action === "pause" && isBrowserHeadless()) {
            throw new Error("browser pause requires a visible browser. Set NUMASEC_BROWSER_HEADLESS=false and retry.")
          }

          yield* ctx.ask({
            permission: "browser",
            patterns: [params.url ?? params.selector ?? params.action],
            always: [],
            metadata: { action: params.action, url: params.url },
          })

          if (params.action === "export_identity") {
            const exported = yield* Effect.promise(() => exportBrowserIdentityState(params, ctx.sessionID))
            const stored = yield* persistExportedBrowserIdentity(exported, ctx)

            const result = {
              title: `identity · ${exported.key}`,
              metadata: {
                action: "export_identity",
                key: exported.key,
                previousIdentity: stored.previous,
                mode: stored.descriptor.mode,
                headerKeys: stored.descriptor.header_keys,
                cookieCount: exported.cookieCount,
                localStorageKeys: exported.localKeys.length,
                sessionStorageKeys: exported.sessionKeys.length,
                currentUrl: exported.currentUrl,
                activeIdentity: exported.key,
              },
              output: [
                `Active identity: ${exported.key}`,
                `Mode: ${stored.descriptor.mode}`,
                `Current URL: ${exported.currentUrl || "(blank page)"}`,
                `Headers: ${stored.descriptor.header_keys.length > 0 ? stored.descriptor.header_keys.join(", ") : "none"}`,
                `Cookies: ${exported.cookieCount}`,
                `localStorage keys inspected: ${exported.localKeys.length}`,
                `sessionStorage keys inspected: ${exported.sessionKeys.length}`,
                "Subsequent http_request calls will automatically reuse this active identity unless you override headers or cookies explicitly.",
              ].join("\n"),
            } satisfies Tool.ExecuteResult

            yield* persistBrowserObservation(params, result, ctx).pipe(Effect.catch(() => Effect.void))
            return result
          }

          const result = yield* Effect.promise(() => run(params, ctx.sessionID))

          if (params.action === "pause") {
            yield* question.ask({
              sessionID: ctx.sessionID,
              tool: ctx.callID ? { messageID: ctx.messageID, callID: ctx.callID } : undefined,
              questions: [
                {
                  header: "Browser",
                  question:
                    "Complete the manual browser step in the visible browser (for example login, SSO, MFA, or a challenge), then choose Continue.",
                  options: [
                    {
                      label: "Continue",
                      description: "Resume automated testing with the current browser session",
                    },
                  ],
                  custom: false,
                },
              ],
            })

            const session = yield* Effect.promise(() => ensure(ctx.sessionID))
            const currentUrl = session.page.url()
            const cookies = yield* Effect.promise(() => session.context.cookies())
            const resumed = {
              ...result,
              title: "Browser resumed",
              metadata: {
                ...result.metadata,
                currentUrl,
                cookieCount: cookies.length,
                resumed: true,
              },
              output: [
                result.output,
                "",
                "Resumed browser session.",
                `Current URL: ${currentUrl || "(blank page)"}`,
                `Cookies: ${cookies.length}`,
                "You can now continue with storage_snapshot, get_cookies, dom_snapshot, or follow-up browser actions.",
              ].join("\n"),
            }
            yield* persistBrowserObservation(params, resumed, ctx).pipe(Effect.catch(() => Effect.void))
            return resumed
          }

          yield* persistBrowserObservation(params, result, ctx).pipe(Effect.catch(() => Effect.void))
          return result
        }).pipe(Effect.orDie),
    }
  }),
)
