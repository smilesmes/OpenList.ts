/**
 * SSRF 出网地址校验。
 *
 * 从 OpenListTeam/OpenList-Worker 的 src/backend/pkg/http.ts 移植（isSafeUrl /
 * assertSafeUrl），去掉 CF 专有的 trusted host 参数，保留核心判定：
 *   - 只允许 http / https
 *   - 拒绝危险主机名（localhost / .local / .internal / metadata 等）
 *   - 拒绝 IPv6 回环、链路本地、唯一本地地址（含 IPv4-mapped 形式）
 *   - 拒绝私有 IPv4 段与回环段
 *
 * 用于管理员可配置的 URL 字段（如 aliyundrive_open 的 api_url_address）在把
 * 凭据发出去之前做一次校验，避免凭据被诱导发往内网或云元数据地址。
 */

/** 私有 / 保留 IPv4 前缀兜底（正则口径之外的补充） */
const PRIVATE_IPV4_PREFIXES = [
  "127.",
  "10.",
  "192.168.",
  "169.254.",
  "0.",
  "100.64.",
  "192.0.0.",
  "192.0.2.",
  "198.18.",
  "198.19.",
]

/** 危险主机名（精确匹配或后缀匹配） */
const DANGEROUS_HOSTS = [
  "localhost",
  ".localhost",
  ".local",
  ".internal",
  ".home.arpa",
  "metadata.google.internal",
  "metadata.azure.com",
  "metadata",
  "169.254.169.254",
]

function isPrivateIPv4(host: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false
  const octets = host.split(".").map((n) => Number(n))
  if (octets.some((n) => n < 0 || n > 255)) return true

  if (octets[0] === 10) return true
  if (octets[0] === 127) return true
  if (octets[0] === 0) return true
  if (octets[0] === 169 && octets[1] === 254) return true
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true
  if (octets[0] === 192 && octets[1] === 168) return true
  if (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) return true
  if (octets[0] >= 224) return true

  return false
}

function isUnsafeIPv6(host: string): boolean {
  const h = host.replace(/^\[/, "").replace(/\]$/, "")
  if (!h.includes(":")) return false
  const lower = h.toLowerCase()

  if (lower === "::1" || lower === "::") return true
  if (lower.startsWith("fe80:")) return true
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true
  if (lower.startsWith("ff")) return true
  const mapped = lower.match(/::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)
  if (mapped) return isPrivateIPv4(mapped[1])

  return false
}

/**
 * 判定 URL 是否为安全的出网目标。
 * 解析失败、协议不符、命中内网/元数据地址一律返回 false。
 */
export function isSafeUrl(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr)
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false

    const host = parsed.hostname.toLowerCase().trim()
    if (!host) return false

    for (const dangerous of DANGEROUS_HOSTS) {
      if (host === dangerous || host.endsWith(dangerous)) return false
    }

    if (isUnsafeIPv6(host)) return false
    if (isPrivateIPv4(host)) return false
    for (const prefix of PRIVATE_IPV4_PREFIXES) {
      if (host.startsWith(prefix)) return false
    }

    return true
  } catch {
    return false
  }
}

/** 不安全时抛错，错误信息带上下文，便于在日志里定位是哪个字段。 */
export function assertSafeUrl(urlStr: string, context = "Request"): void {
  if (!isSafeUrl(urlStr)) {
    throw new Error(
      `${context} blocked: URL points to a restricted or private network destination (SSRF protection)`,
    )
  }
}
