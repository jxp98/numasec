const GITHUB_APP_API_BASE_URL_ENV = "NUMASEC_GITHUB_APP_API_BASE_URL"
const OIDC_BASE_URL_ENV = "OIDC_BASE_URL"

function requireBaseUrl(envName: string, message: string) {
  const value = process.env[envName]?.trim()
  if (!value) throw new Error(message)
  return value.replace(/\/+$/, "")
}

export function requireGitHubAppApiBaseUrl() {
  return requireBaseUrl(
    GITHUB_APP_API_BASE_URL_ENV,
    `GitHub install lookup is disabled by default. Set ${GITHUB_APP_API_BASE_URL_ENV} to an explicitly trusted base URL to re-enable it.`,
  )
}

export function requireOidcBaseUrl() {
  return requireBaseUrl(
    OIDC_BASE_URL_ENV,
    `Hosted GitHub token exchange is disabled by default. Set ${OIDC_BASE_URL_ENV} to an explicitly trusted base URL, or set USE_GITHUB_TOKEN=true with GITHUB_TOKEN to avoid remote exchange.`,
  )
}
