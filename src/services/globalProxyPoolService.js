const redis = require('../models/redis')
const ProxyHelper = require('../utils/proxyHelper')
const logger = require('../utils/logger')

const OEM_SETTINGS_KEY = 'oem:settings'

const ACCOUNT_SOURCES = [
  {
    platform: 'claude',
    indexKey: 'claude:account:index',
    keyPattern: 'claude:account:*',
    keyPrefix: 'claude:account:',
    idPattern: /^claude:account:(.+)$/
  },
  {
    platform: 'claude-console',
    indexKey: 'claude_console_account:index',
    keyPattern: 'claude_console_account:*',
    keyPrefix: 'claude_console_account:',
    idPattern: /^claude_console_account:(.+)$/
  },
  {
    platform: 'ccr',
    indexKey: 'ccr_account:index',
    keyPattern: 'ccr_account:*',
    keyPrefix: 'ccr_account:',
    idPattern: /^ccr_account:(.+)$/
  },
  {
    platform: 'gemini',
    indexKey: 'gemini_account:index',
    keyPattern: 'gemini_account:*',
    keyPrefix: 'gemini_account:',
    idPattern: /^gemini_account:(.+)$/
  },
  {
    platform: 'gemini-api',
    indexKey: 'gemini_api_account:index',
    keyPattern: 'gemini_api_account:*',
    keyPrefix: 'gemini_api_account:',
    idPattern: /^gemini_api_account:(.+)$/
  },
  {
    platform: 'openai',
    indexKey: 'openai:account:index',
    keyPattern: 'openai:account:*',
    keyPrefix: 'openai:account:',
    idPattern: /^openai:account:(.+)$/
  },
  {
    platform: 'openai-responses',
    indexKey: 'openai_responses_account:index',
    keyPattern: 'openai_responses_account:*',
    keyPrefix: 'openai_responses_account:',
    idPattern: /^openai_responses_account:(.+)$/
  },
  {
    platform: 'azure-openai',
    indexKey: 'azure_openai:account:index',
    keyPattern: 'azure_openai:account:*',
    keyPrefix: 'azure_openai:account:',
    idPattern: /^azure_openai:account:(.+)$/
  },
  {
    platform: 'droid',
    indexKey: 'droid:account:index',
    keyPattern: 'droid:account:*',
    keyPrefix: 'droid:account:',
    idPattern: /^droid:account:(.+)$/
  }
]

function buildDefaultConfig() {
  return {
    enabled: false,
    autoAssignOnCreate: true,
    proxies: [],
    updatedAt: null
  }
}

function cloneProxy(proxy) {
  if (!proxy) {
    return null
  }
  return JSON.parse(JSON.stringify(proxy))
}

function normalizeProxyObject(proxy) {
  if (!proxy || typeof proxy !== 'object') {
    return null
  }

  const normalized = {
    type: typeof proxy.type === 'string' ? proxy.type.trim().toLowerCase() : '',
    host: typeof proxy.host === 'string' ? proxy.host.trim() : String(proxy.host || '').trim(),
    port: Number.parseInt(proxy.port, 10),
    username:
      typeof proxy.username === 'string'
        ? proxy.username
        : proxy.username !== undefined && proxy.username !== null
          ? String(proxy.username)
          : '',
    password:
      typeof proxy.password === 'string'
        ? proxy.password
        : proxy.password !== undefined && proxy.password !== null
          ? String(proxy.password)
          : ''
  }

  if (!ProxyHelper.validateProxyConfig(normalized)) {
    return null
  }

  return normalized
}

function parseProxyUrlLine(line) {
  const parsed = new URL(line)
  const type = parsed.protocol.replace(/:$/, '').toLowerCase()
  const normalized = {
    type,
    host: parsed.hostname,
    port: Number.parseInt(parsed.port, 10),
    username: parsed.username ? decodeURIComponent(parsed.username) : '',
    password: parsed.password ? decodeURIComponent(parsed.password) : ''
  }

  return normalizeProxyObject(normalized)
}

function parseProxyCsvLine(line) {
  const parts = line.split(',').map((part) => part.trim())
  if (parts.length < 3) {
    return null
  }

  const [type, host, port, username = '', password = ''] = parts
  return normalizeProxyObject({
    type,
    host,
    port,
    username,
    password
  })
}

function parseProxyLine(line) {
  const trimmed = typeof line === 'string' ? line.trim() : ''
  if (!trimmed) {
    return null
  }

  if (trimmed.includes('://')) {
    return parseProxyUrlLine(trimmed)
  }

  if (trimmed.includes(',')) {
    return parseProxyCsvLine(trimmed)
  }

  return null
}

class GlobalProxyPoolService {
  async getConfig() {
    const client = redis.getClientSafe()
    const raw = await client.get(OEM_SETTINGS_KEY)
    const defaults = buildDefaultConfig()

    if (!raw) {
      return defaults
    }

    try {
      const settings = JSON.parse(raw)
      const normalized = this.normalizeConfig(settings.globalProxyPool || {})
      return normalized
    } catch (error) {
      logger.warn('⚠️ Failed to parse global proxy pool settings:', error.message)
      return defaults
    }
  }

  normalizeConfig(input = {}) {
    const rawProxies = Array.isArray(input.proxies) ? input.proxies : []

    return {
      enabled: input.enabled === true,
      autoAssignOnCreate: input.autoAssignOnCreate !== false,
      proxies: this.normalizeProxyList(rawProxies),
      updatedAt: input.updatedAt || null
    }
  }

  normalizeProxyList(rawProxies = []) {
    const normalized = []

    for (const entry of rawProxies) {
      const proxy =
        typeof entry === 'string' ? parseProxyLine(entry) : normalizeProxyObject(entry || null)
      if (proxy) {
        normalized.push(proxy)
      }
    }

    return normalized
  }

  parseProxyTextarea(text = '') {
    if (typeof text !== 'string' || !text.trim()) {
      return []
    }

    return this.normalizeProxyList(
      text
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
    )
  }

  async assignProxyIfNeeded(currentProxy, options = {}) {
    if (currentProxy) {
      return currentProxy
    }

    const config = options.config || (await this.getConfig())
    if (!config.enabled || config.autoAssignOnCreate === false || config.proxies.length === 0) {
      return null
    }

    return this.pickRandomProxy(config.proxies)
  }

  pickRandomProxy(proxies = []) {
    if (!Array.isArray(proxies) || proxies.length === 0) {
      return null
    }

    const index = Math.floor(Math.random() * proxies.length)
    return cloneProxy(proxies[index])
  }

  async assignMissingProxiesToAllAccounts(configOverride = null) {
    const config = configOverride ? this.normalizeConfig(configOverride) : await this.getConfig()
    if (!config.enabled) {
      throw new Error('Global proxy pool is disabled')
    }

    if (config.proxies.length === 0) {
      throw new Error('Global proxy pool has no valid proxies configured')
    }

    const client = redis.getClientSafe()
    const result = {
      assignedCount: 0,
      scannedCount: 0,
      skippedCount: 0,
      accountsByPlatform: {}
    }

    for (const source of ACCOUNT_SOURCES) {
      const accountIds = await redis.getAllIdsByIndex(
        source.indexKey,
        source.keyPattern,
        source.idPattern
      )

      result.accountsByPlatform[source.platform] = {
        assigned: 0,
        scanned: accountIds.length
      }
      result.scannedCount += accountIds.length

      if (accountIds.length === 0) {
        continue
      }

      const keys = accountIds.map((id) => `${source.keyPrefix}${id}`)
      const records = await redis.batchHgetallChunked(keys)

      for (let i = 0; i < records.length; i++) {
        const record = records[i]
        if (!record || Object.keys(record).length === 0) {
          result.skippedCount++
          continue
        }

        if (record.proxy && String(record.proxy).trim()) {
          result.skippedCount++
          continue
        }

        const proxy = this.pickRandomProxy(config.proxies)
        if (!proxy) {
          result.skippedCount++
          continue
        }

        await client.hset(keys[i], 'proxy', JSON.stringify(proxy))
        result.assignedCount++
        result.accountsByPlatform[source.platform].assigned++
      }
    }

    return result
  }
}

module.exports = new GlobalProxyPoolService()
module.exports.GlobalProxyPoolService = GlobalProxyPoolService
module.exports.parseProxyLine = parseProxyLine
module.exports.normalizeProxyObject = normalizeProxyObject
