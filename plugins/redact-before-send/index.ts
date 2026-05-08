import type { Part } from "@numasec/sdk"
import {
  redactBeforeSendMessagesInPlace,
  redactBeforeSendSystemInPlace,
  type RedactBeforeSendOptions,
} from "../../packages/numasec/src/plugin/redact-before-send"

export default async function redactBeforeSendPlugin(_input: unknown, options?: RedactBeforeSendOptions) {
  const resolved = options ?? {}
  return {
    "experimental.chat.messages.transform": (_input: unknown, output: { messages: Array<{ parts: Part[] }> }) => {
      redactBeforeSendMessagesInPlace(output.messages, resolved)
    },
    "experimental.chat.system.transform": (_input: unknown, output: { system: string[] }) => {
      redactBeforeSendSystemInPlace(output.system, resolved)
    },
  }
}
