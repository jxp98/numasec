import type { FilePart, Part, TextPart } from "@numasec/sdk"

export type RedactBeforeSendOptions = {
  dropAttachments?: boolean
  blockOnRawIdCard?: boolean
}

type KeyKind = "name" | "phone" | "idCard" | "authorization" | "cookie" | "secret"

type MessageWithParts = {
  parts: Part[]
}

const NAME_KEYS = [
  "name",
  "fullname",
  "realname",
  "legalname",
  "firstname",
  "lastname",
  "middlename",
  "givenname",
  "familyname",
  "surname",
  "contactname",
  "receivername",
  "recipientname",
  "applicantname",
  "ownername",
  "beneficiaryname",
  "customername",
  "姓名",
  "真实姓名",
  "联系人",
  "联系人姓名",
  "收件人",
  "收件人姓名",
  "申请人",
  "法人",
  "持卡人",
  "客户姓名",
  "用户姓名",
  "受益人姓名",
] as const

const PHONE_KEYS = [
  "phone",
  "phonenumber",
  "mobile",
  "mobilenumber",
  "mobilephone",
  "cellphone",
  "telephone",
  "tel",
  "phoneno",
  "contactphone",
  "receiverphone",
  "recipientphone",
  "applicantphone",
  "ownerphone",
  "beneficiaryphone",
  "contactnumber",
  "手机",
  "手机号",
  "手机号码",
  "电话",
  "电话号码",
  "联系电话",
  "联系方式",
  "联系人电话",
  "收件人电话",
] as const

const IDCARD_KEYS = [
  "idcard",
  "idcardno",
  "idcardnumber",
  "identitycard",
  "identitynumber",
  "identityno",
  "nationalid",
  "nationalidnumber",
  "citizenid",
  "citizenidnumber",
  "身份证",
  "身份证号",
  "身份证号码",
  "公民身份号码",
  "证件号",
  "证件号码",
] as const

const AUTHORIZATION_KEYS = ["authorization", "proxyauthorization"] as const
const COOKIE_KEYS = ["cookie", "cookies", "setcookie", "set-cookie"] as const
const SECRET_KEYS = [
  "password",
  "passwd",
  "pass",
  "secret",
  "token",
  "accesstoken",
  "refreshtoken",
  "apikey",
  "api_key",
  "clientsecret",
  "privatekey",
  "sessiontoken",
  "sessionkey",
  "jwt",
] as const

const FIELD_NAME_LABELS = [
  "name",
  "fullName",
  "realName",
  "legalName",
  "firstName",
  "lastName",
  "middleName",
  "givenName",
  "familyName",
  "surname",
  "contactName",
  "receiverName",
  "recipientName",
  "applicantName",
  "ownerName",
  "beneficiaryName",
  "姓名",
  "真实姓名",
  "联系人",
  "联系人姓名",
  "收件人",
  "收件人姓名",
  "申请人",
  "法人",
  "持卡人",
  "客户姓名",
  "用户姓名",
] as const

const FIELD_PHONE_LABELS = [
  "phone",
  "phoneNumber",
  "mobile",
  "mobileNumber",
  "mobilePhone",
  "cellphone",
  "telephone",
  "tel",
  "contactPhone",
  "receiverPhone",
  "recipientPhone",
  "applicantPhone",
  "ownerPhone",
  "beneficiaryPhone",
  "手机号",
  "手机号码",
  "联系电话",
  "联系方式",
  "联系人电话",
] as const

const FIELD_ID_LABELS = [
  "idCard",
  "idCardNo",
  "idCardNumber",
  "identityCard",
  "identityNumber",
  "identityNo",
  "nationalId",
  "citizenId",
  "身份证",
  "身份证号",
  "身份证号码",
  "公民身份号码",
  "证件号",
  "证件号码",
] as const

const FIELD_SECRET_LABELS = [
  "token",
  "access_token",
  "accessToken",
  "refresh_token",
  "refreshToken",
  "api_key",
  "apiKey",
  "secret",
  "password",
  "passwd",
  "jwt",
] as const

const NAME_KEY_SET = new Set(NAME_KEYS)
const PHONE_KEY_SET = new Set(PHONE_KEYS)
const IDCARD_KEY_SET = new Set(IDCARD_KEYS)
const AUTHORIZATION_KEY_SET = new Set(AUTHORIZATION_KEYS)
const COOKIE_KEY_SET = new Set(COOKIE_KEYS)
const SECRET_KEY_SET = new Set(SECRET_KEYS)

const JWT_RE = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g
const BEARER_RE = /\bBearer\s+([A-Za-z0-9._~+/=-]{8,})/gi
const AUTH_LINE_RE = /\b(Authorization|Proxy-Authorization)\s*:\s*([^\r\n]+)/gi
const COOKIE_LINE_RE = /\bCookie\s*:\s*([^\r\n]+)/gi
const SET_COOKIE_LINE_RE = /\bSet-Cookie\s*:\s*([^\r\n]+)/gi
const CN_MOBILE_RE = /(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)/g
const CN_ID_RE = /(?<![0-9Xx])(?:[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx])(?![0-9Xx])/g

const TEXT_KEY_EXCLUSIONS = new Set(["hostname", "filename", "pathname", "username", "sessionid", "requestid"])

export function normalizeKey(input: string): string {
  return input.toLowerCase().replace(/[\s_\-.:[\]{}()]/g, "")
}

export function classifyKeyPath(path: string[]): KeyKind | undefined {
  for (let index = path.length - 1; index >= 0; index -= 1) {
    const normalized = normalizeKey(path[index] ?? "")
    if (!normalized) continue
    if (TEXT_KEY_EXCLUSIONS.has(normalized)) return undefined
    if (AUTHORIZATION_KEY_SET.has(normalized)) return "authorization"
    if (COOKIE_KEY_SET.has(normalized)) return "cookie"
    if (IDCARD_KEY_SET.has(normalized)) return "idCard"
    if (PHONE_KEY_SET.has(normalized)) return "phone"
    if (NAME_KEY_SET.has(normalized)) return "name"
    if (SECRET_KEY_SET.has(normalized)) return "secret"
  }
  return undefined
}

export function redactBeforeSendMessagesInPlace(messages: MessageWithParts[], options: RedactBeforeSendOptions = {}): void {
  for (const message of messages) {
    message.parts = message.parts.map((part) => redactBeforeSendPart(part, options))
  }
}

export function redactBeforeSendSystemInPlace(system: string[], options: RedactBeforeSendOptions = {}): void {
  for (let index = 0; index < system.length; index += 1) {
    system[index] = redactText(system[index] ?? "", options)
  }
}

export function redactBeforeSendPart(part: Part, options: RedactBeforeSendOptions = {}): Part {
  switch (part.type) {
    case "text":
      return {
        ...part,
        text: redactText(part.text, options),
      }
    case "reasoning":
      return {
        ...part,
        text: redactText(part.text, options),
      }
    case "subtask":
      return {
        ...part,
        prompt: redactText(part.prompt, options),
        description: redactText(part.description, options),
      }
    case "tool":
      return {
        ...part,
        state:
          part.state.status === "pending"
            ? {
                ...part.state,
                input: redactValue(part.state.input, options),
                raw: redactText(part.state.raw, options),
              }
            : part.state.status === "running"
              ? {
                  ...part.state,
                  input: redactValue(part.state.input, options),
                  title: part.state.title === undefined ? undefined : redactText(part.state.title, options),
                }
              : part.state.status === "completed"
                ? {
                    ...part.state,
                    input: redactValue(part.state.input, options),
                    output: appendAttachmentNotice(redactText(part.state.output, options), part.state.attachments, options),
                    title: redactText(part.state.title, options),
                    attachments: options.dropAttachments
                      ? []
                      : part.state.attachments?.map((item) => redactFilePart(item, options)),
                  }
                : {
                    ...part.state,
                    input: redactValue(part.state.input, options),
                    error: redactText(part.state.error, options),
                  },
      }
    case "file":
      return options.dropAttachments ? filePartToPlaceholder(part, options) : redactFilePart(part, options)
    case "snapshot":
      return {
        ...part,
        snapshot: redactText(part.snapshot, options),
      }
    case "agent":
      return {
        ...part,
        source: part.source
          ? {
              ...part.source,
              value: redactText(part.source.value, options),
            }
          : part.source,
      }
    default:
      return part
  }
}

export function redactValue(value: unknown, options: RedactBeforeSendOptions = {}, path: string[] = []): unknown {
  if (value === null || value === undefined) return value
  const kind = classifyKeyPath(path)
  if (typeof value === "string") return redactStringByKind(value, kind, options, path[path.length - 1])
  if (Array.isArray(value)) return value.map((item) => redactValue(item, options, path))
  if (typeof value === "object") {
    const output: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      output[key] = redactValue(item, options, [...path, key])
    }
    return output
  }
  return value
}

export function redactText(value: string, options: RedactBeforeSendOptions = {}): string {
  assertNoRawIdCard(value, options)

  let output = value
  output = output.replace(AUTH_LINE_RE, (_match, key: string, raw: string) => `${key}: ${summarizeAuthorization(raw.trim())}`)
  output = output.replace(COOKIE_LINE_RE, (_match, raw: string) => `Cookie: ${summarizeCookie(raw.trim())}`)
  output = output.replace(SET_COOKIE_LINE_RE, (_match, raw: string) => `Set-Cookie: ${summarizeSetCookie(raw.trim())}`)
  output = output.replace(BEARER_RE, (_match, token: string) => `Bearer ${summarizeToken(token, "bearer")}`)
  output = output.replace(JWT_RE, (token) => summarizeJwt(token))
  output = replaceQuotedKeyValues(output, FIELD_SECRET_LABELS, (key, raw) => summarizeSecretValue(raw.trim(), key))
  output = replaceQueryKeyValues(output, FIELD_SECRET_LABELS, (key, raw) => summarizeSecretValue(raw.trim(), key))
  output = replaceLabeledValues(output, FIELD_SECRET_LABELS, (key, raw) => summarizeSecretValue(raw.trim(), key))
  output = replaceQuotedKeyValues(output, FIELD_NAME_LABELS, () => "[redacted:name]")
  output = replaceQueryKeyValues(output, FIELD_NAME_LABELS, () => "[redacted:name]")
  output = replaceLabeledValues(output, FIELD_NAME_LABELS, () => "[redacted:name]")
  output = output.replace(CN_MOBILE_RE, (raw) => summarizePhone(raw))
  output = output.replace(CN_ID_RE, (raw) => summarizeIdCard(raw))
  output = replaceQuotedKeyValues(output, FIELD_PHONE_LABELS, (_key, raw) => summarizePhone(raw.trim()))
  output = replaceQueryKeyValues(output, FIELD_PHONE_LABELS, (_key, raw) => summarizePhone(raw.trim()))
  output = replaceLabeledValues(output, FIELD_PHONE_LABELS, (_key, raw) => summarizePhone(raw.trim()))
  output = replaceQuotedKeyValues(output, FIELD_ID_LABELS, (_key, raw) => summarizeIdCard(raw.trim()))
  output = replaceQueryKeyValues(output, FIELD_ID_LABELS, (_key, raw) => summarizeIdCard(raw.trim()))
  output = replaceLabeledValues(output, FIELD_ID_LABELS, (_key, raw) => summarizeIdCard(raw.trim()))
  return output
}

export function assertNoRawIdCard(value: string, options: RedactBeforeSendOptions = {}): void {
  if (!options.blockOnRawIdCard) return
  CN_ID_RE.lastIndex = 0
  if (!CN_ID_RE.test(value)) return
  throw new Error("发送前脱敏插件已拦截：检测到疑似未脱敏身份证号")
}

export function summarizeJwt(token: string): string {
  const [headerPart, payloadPart] = token.split(".")
  const header = parseJwtSegment(headerPart)
  const payload = parseJwtSegment(payloadPart)
  const alg = typeof header?.alg === "string" ? header.alg : "?"
  const typ = typeof header?.typ === "string" ? header.typ : "?"
  const payloadKeys = Object.keys(payload ?? {}).slice(0, 6)
  const suffix = payloadKeys.length > 0 ? ` payload_keys=${payloadKeys.join(",")}` : ""
  return `[redacted:jwt alg=${alg} typ=${typ}${suffix}]`
}

function redactFilePart(part: FilePart, options: RedactBeforeSendOptions): FilePart {
  return {
    ...part,
    filename: part.filename === undefined ? undefined : redactText(part.filename, options),
  }
}

function filePartToPlaceholder(part: FilePart, options: RedactBeforeSendOptions): TextPart {
  const filename = part.filename ? ` ${redactText(part.filename, options)}` : ""
  return {
    id: part.id,
    sessionID: part.sessionID,
    messageID: part.messageID,
    type: "text",
    synthetic: true,
    text: `[已移除附件: ${part.mime}${filename}]`,
  }
}

function appendAttachmentNotice(output: string, attachments: FilePart[] | undefined, options: RedactBeforeSendOptions): string {
  if (!options.dropAttachments || !attachments || attachments.length === 0) return output
  return `${output}\n[已在发送前移除 ${attachments.length} 个附件]`
}

function redactStringByKind(
  value: string,
  kind: KeyKind | undefined,
  options: RedactBeforeSendOptions,
  keyHint?: string,
): string {
  assertNoRawIdCard(value, options)
  if (kind === "name") return value.trim() ? "[redacted:name]" : value
  if (kind === "phone") return summarizePhone(value)
  if (kind === "idCard") return summarizeIdCard(value)
  if (kind === "authorization") return summarizeAuthorization(value)
  if (kind === "cookie") return value.includes("=") ? summarizeCookie(value) : summarizeSecretValue(value, keyHint)
  if (kind === "secret") return summarizeSecretValue(value, keyHint)
  return redactText(value, options)
}

function summarizePhone(value: string): string {
  if (value.includes("[redacted:")) return value
  const match = value.match(/(\d{4})(?!.*\d)/)
  return match ? `[redacted:phone:tail=${match[1]}]` : "[redacted:phone]"
}

function summarizeIdCard(value: string): string {
  if (value.includes("[redacted:")) return value
  const clean = value.replace(/\s+/g, "")
  const tail = clean.slice(-4)
  return tail ? `[redacted:cn-id:tail=${tail}]` : "[redacted:cn-id]"
}

function summarizeAuthorization(value: string): string {
  if (!value.trim()) return value
  const [scheme, ...rest] = value.trim().split(/\s+/)
  const token = rest.join(" ")
  if (!scheme) return "[redacted:authorization]"
  if (token.startsWith("[redacted:")) return `${scheme} ${token}`.trim()
  const lowered = scheme.toLowerCase()
  if (lowered === "bearer") return `Bearer ${summarizeToken(token, "bearer")}`
  if (lowered === "basic") return `Basic [redacted:basic len=${token.length}]`
  if (lowered === "token") return `Token ${summarizeToken(token, "token")}`
  return `[redacted:authorization scheme=${scheme} len=${value.trim().length}]`
}

function summarizeSecretValue(value: string, keyHint?: string): string {
  const normalizedKey = keyHint ? normalizeKey(keyHint) : undefined
  if (!value.trim()) return value
  if (value.includes("[redacted:")) return value
  if (normalizedKey && (normalizedKey === "cookie" || normalizedKey === "cookies")) return summarizeCookie(value)
  if (normalizedKey && normalizedKey === "setcookie") return summarizeSetCookie(value)
  if (/^bearer\s+/i.test(value)) return summarizeAuthorization(value)
  return summarizeToken(value, "secret", keyHint)
}

function summarizeToken(value: string, label: string, keyHint?: string): string {
  if (!value.trim()) return value
  if (value.startsWith("[redacted:")) return value
  if (looksLikeJwt(value)) return summarizeJwt(value)
  const keyPart = keyHint ? ` key=${keyHint}` : ""
  return `[redacted:${label}${keyPart} len=${value.length}]`
}

function summarizeCookie(value: string): string {
  if (value.includes("[redacted:")) return value
  const parts = value
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
  if (parts.length === 0) return "[redacted:cookie]"
  return parts
    .map((item) => {
      const equals = item.indexOf("=")
      if (equals === -1) return item
      const key = item.slice(0, equals).trim()
      const raw = item.slice(equals + 1).trim()
      return `${key}=[redacted:cookie-value len=${raw.length}]`
    })
    .join("; ")
}

function summarizeSetCookie(value: string): string {
  if (value.includes("[redacted:")) return value
  const parts = value
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
  if (parts.length === 0) return "[redacted:set-cookie]"
  const [head, ...flags] = parts
  const equals = head.indexOf("=")
  const redactedHead =
    equals === -1
      ? "[redacted:set-cookie]"
      : `${head.slice(0, equals).trim()}=[redacted:cookie-value len=${head.slice(equals + 1).trim().length}]`
  return [redactedHead, ...flags].join("; ")
}

function looksLikeJwt(value: string): boolean {
  return value.split(".").length === 3 && value.startsWith("eyJ")
}

function parseJwtSegment(segment: string | undefined): Record<string, unknown> | undefined {
  if (!segment) return undefined
  try {
    const normalized = segment.replace(/-/g, "+").replace(/_/g, "/")
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4)
    return JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as Record<string, unknown>
  } catch {
    return undefined
  }
}

function replaceQuotedKeyValues(
  text: string,
  keys: readonly string[],
  redact: (key: string, raw: string) => string,
): string {
  const keyAlt = buildAlternation(keys)
  const pattern = new RegExp(`(["'](?:${keyAlt})["']\\s*:\\s*["'])([^"'\\r\\n]*)(["'])`, "giu")
  return text.replace(pattern, (_match, prefix: string, raw: string, suffix: string) => {
    return `${prefix}${redact(extractKey(prefix), raw)}${suffix}`
  })
}

function replaceQueryKeyValues(
  text: string,
  keys: readonly string[],
  redact: (key: string, raw: string) => string,
): string {
  const keyAlt = buildAlternation(keys)
  const pattern = new RegExp(`((?:^|[?&\\s])(?:${keyAlt})=)([^&#\\s]+)`, "giu")
  return text.replace(pattern, (_match, prefix: string, raw: string) => `${prefix}${redact(extractKey(prefix), raw)}`)
}

function replaceLabeledValues(
  text: string,
  keys: readonly string[],
  redact: (key: string, raw: string) => string,
): string {
  const keyAlt = buildAlternation(keys)
  const pattern = new RegExp(`((?:^|[\\s\\r\\n])(?:${keyAlt})\\s*[:：]\\s*)([^\\r\\n,，;；]+)`, "giu")
  return text.replace(pattern, (_match, prefix: string, raw: string) => {
    const split = splitInlineAssignmentSuffix(raw.trim())
    return `${prefix}${redact(extractKey(prefix), split.value)}${split.suffix}`
  })
}

function buildAlternation(keys: readonly string[]): string {
  return [...keys].sort((left, right) => right.length - left.length).map(escapeRegExp).join("|")
}

function splitInlineAssignmentSuffix(raw: string): { value: string; suffix: string } {
  const match = raw.match(/^(.*?)(\s+(?:["']?[\p{L}_][\p{L}\p{N}_-]*["']?\s*[:=].*))$/u)
  if (!match) return { value: raw, suffix: "" }
  return { value: match[1]?.trimEnd() ?? raw, suffix: match[2] ?? "" }
}

function extractKey(prefix: string): string {
  const match = prefix.match(/([\p{L}_-][\p{L}\p{N}_-]*)/u)
  return match?.[1] ?? ""
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}
