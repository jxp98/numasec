# 发送前脱敏插件

这个路径插件会在消息与 system prompt 发送给模型 Provider 之前做最小脱敏。

## 覆盖范围

- 中文姓名：优先按字段语义与标签文本脱敏
- 手机号：支持常见手机号字段与文本中的中国大陆手机号
- 身份证号：支持常见身份证字段与文本中的 18 位中国大陆身份证号
- Secret / Token：支持 `token`、`access_token`、`refresh_token`、`api_key`、`password` 等字段
- `Authorization`：保留方案名，JWT 保留 `alg` / `typ` / `payload_keys`
- `Cookie` / `Set-Cookie`：保留键名与属性标志，脱敏值

## 启用方式

在你的 `numasec.json` 里加入：

```json
{
  "plugin": [
    ["./plugins/redact-before-send", { "dropAttachments": false, "blockOnRawIdCard": false }]
  ]
}
```

## 可选项

- `dropAttachments`
  - `true`：发送给模型前移除附件，并在文本里补一条提示
  - `false`：保留附件，仅处理文件名中的可见敏感信息
- `blockOnRawIdCard`
  - `true`：如果检测到原始身份证号，直接阻断送模
  - `false`：仅脱敏后继续发送

## 说明

- 这个插件只处理**发送给模型前**的内容。
- 本地会话、数据库、回放证据是否保留原文，取决于其他链路是否也做了入库前脱敏。
