import { describe, expect, test } from "bun:test"
import type { Part } from "@numasec/sdk"
import {
  assertNoRawIdCard,
  classifyKeyPath,
  redactBeforeSendMessagesInPlace,
  redactBeforeSendPart,
  redactText,
  redactValue,
  summarizeJwt,
} from "../../src/plugin/redact-before-send"

describe("redact-before-send", () => {
  test("按字段语义脱敏姓名、手机号、身份证号", () => {
    const output = redactValue({
      fullName: "张三",
      firstName: "三",
      lastName: "张",
      contactPhone: "13800138000",
      idCardNo: "110101199001011234",
      username: "security-admin",
      hostname: "demo.internal",
    }) as Record<string, unknown>

    expect(output.fullName).toBe("[redacted:name]")
    expect(output.firstName).toBe("[redacted:name]")
    expect(output.lastName).toBe("[redacted:name]")
    expect(output.contactPhone).toBe("[redacted:phone:tail=8000]")
    expect(output.idCardNo).toBe("[redacted:cn-id:tail=1234]")
    expect(output.username).toBe("security-admin")
    expect(output.hostname).toBe("demo.internal")
  })

  test("脱敏文本中的中文标签与通用密钥", () => {
    const input = [
      "姓名: 张三",
      "手机号: 13800138000",
      "身份证号: 110101199001011234",
      "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3MDAwMDAwMDB9.signature",
      "token=abcd1234efgh5678",
    ].join("\n")

    const output = redactText(input)

    expect(output).toContain("姓名: [redacted:name]")
    expect(output).toContain("手机号: [redacted:phone:tail=8000]")
    expect(output).toContain("身份证号: [redacted:cn-id:tail=1234]")
    expect(output).toContain("Authorization: Bearer [redacted:jwt alg=HS256 typ=JWT payload_keys=sub,role,exp]")
    expect(output).toContain("token=[redacted:secret key=token len=16]")
    expect(output).not.toContain("110101199001011234")
  })

  test("保留 Set-Cookie 标志位但脱敏值", () => {
    const output = redactText("Set-Cookie: session=abcdef123456; Path=/; HttpOnly; Secure; SameSite=Lax")

    expect(output).toBe(
      "Set-Cookie: session=[redacted:cookie-value len=12]; Path=/; HttpOnly; Secure; SameSite=Lax",
    )
  })

  test("可拦截未脱敏身份证号", () => {
    expect(() => assertNoRawIdCard("身份证号 110101199001011234", { blockOnRawIdCard: true })).toThrow(
      "发送前脱敏插件已拦截：检测到疑似未脱敏身份证号",
    )
  })

  test("按 part 脱敏工具输出并可移除附件", () => {
    const part: Part = {
      id: "part-1",
      sessionID: "session-1",
      messageID: "message-1",
      type: "tool",
      callID: "call-1",
      tool: "http_request",
      state: {
        status: "completed",
        input: {
          headers: {
            Authorization: "Bearer secret-token-value",
          },
          firstName: "张三",
        },
        output: "Cookie: sid=abcdef; csrftoken=qwerty\n手机号: 13800138000",
        title: "请求结果",
        metadata: {},
        time: {
          start: 1,
          end: 2,
        },
        attachments: [
          {
            id: "file-1",
            sessionID: "session-1",
            messageID: "message-1",
            type: "file",
            mime: "image/png",
            filename: "张三-截图.png",
            url: "data:image/png;base64,AA==",
          },
        ],
      },
    }

    const output = redactBeforeSendPart(part, { dropAttachments: true })

    expect(output.type).toBe("tool")
    if (output.type !== "tool" || output.state.status !== "completed") throw new Error("unexpected part")

    const stateInput = output.state.input as {
      headers: { Authorization: string }
      firstName: string
    }

    expect(stateInput.headers.Authorization).toBe("Bearer [redacted:bearer len=18]")
    expect(stateInput.firstName).toBe("[redacted:name]")
    expect(output.state.output).toContain("Cookie: sid=[redacted:cookie-value len=6]; csrftoken=[redacted:cookie-value len=6]")
    expect(output.state.output).toContain("手机号: [redacted:phone:tail=8000]")
    expect(output.state.output).toContain("[已在发送前移除 1 个附件]")
    expect(output.state.attachments).toEqual([])
  })

  test("批量消息就地脱敏", () => {
    const messages: Array<{ parts: Part[] }> = [
      {
        parts: [
          {
            id: "text-1",
            sessionID: "session-1",
            messageID: "message-1",
            type: "text",
            text: "姓名: 李四 token=tok_12345678",
          },
        ],
      },
    ]

    redactBeforeSendMessagesInPlace(messages)

    const part = messages[0]?.parts[0]
    expect(part?.type).toBe("text")
    if (part?.type !== "text") throw new Error("unexpected part")
    expect(part.text).toContain("姓名: [redacted:name]")
    expect(part.text).toContain("token=[redacted:secret key=token len=12]")
  })

  test("键路径分类避免误伤 hostname 等字段", () => {
    expect(classifyKeyPath(["user", "firstName"]))toBe("name")
    expect(classifyKeyPath(["contactPhone"]))toBe("phone")
    expect(classifyKeyPath(["identityNumber"]))toBe("idCard")
    expect(classifyKeyPath(["Authorization"]))toBe("authorization")
    expect(classifyKeyPath(["hostname"]))toBeUndefined()
    expect(classifyKeyPath(["filename"]))toBeUndefined()
    expect(classifyKeyPath(["pathname"]))toBeUndefined()
    expect(classifyKeyPath(["requestId"]))toBeUndefined()
  })

  test("JWT 摘要保留结构信息", () => {
    const output = summarizeJwt(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3MDAwMDAwMDB9.signature",
    )

    expect(output).toBe("[redacted:jwt alg=HS256 typ=JWT payload_keys=sub,role,exp]")
  })
})
