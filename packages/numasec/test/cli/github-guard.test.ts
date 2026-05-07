import { afterEach, describe, expect, test } from "bun:test"
import { requireGitHubAppApiBaseUrl, requireOidcBaseUrl } from "../../src/cli/cmd/github-guard"

const previousGitHubAppApiBaseUrl = process.env["NUMASEC_GITHUB_APP_API_BASE_URL"]
const previousOidcBaseUrl = process.env["OIDC_BASE_URL"]

afterEach(() => {
  if (previousGitHubAppApiBaseUrl === undefined) delete process.env["NUMASEC_GITHUB_APP_API_BASE_URL"]
  else process.env["NUMASEC_GITHUB_APP_API_BASE_URL"] = previousGitHubAppApiBaseUrl

  if (previousOidcBaseUrl === undefined) delete process.env["OIDC_BASE_URL"]
  else process.env["OIDC_BASE_URL"] = previousOidcBaseUrl
})

describe("github guard", () => {
  test("GitHub 安装查询默认关闭", () => {
    delete process.env["NUMASEC_GITHUB_APP_API_BASE_URL"]
    expect(() => requireGitHubAppApiBaseUrl()).toThrow("disabled by default")
  })

  test("GitHub 安装查询要求显式 base URL", () => {
    process.env["NUMASEC_GITHUB_APP_API_BASE_URL"] = "https://api.numasec.ai///"
    expect(requireGitHubAppApiBaseUrl()).toBe("https://api.numasec.ai")
  })

  test("OIDC token 交换默认关闭", () => {
    delete process.env["OIDC_BASE_URL"]
    expect(() => requireOidcBaseUrl()).toThrow("disabled by default")
  })

  test("OIDC token 交换要求显式 base URL", () => {
    process.env["OIDC_BASE_URL"] = "https://trusted.example.com///"
    expect(requireOidcBaseUrl()).toBe("https://trusted.example.com")
  })
})
