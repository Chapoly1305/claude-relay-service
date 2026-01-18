/**
 * Claude Code Headers 管理服务
 * 现在仅负责返回平台统一的固定 Headers，不再进行客户端 Headers 捕获和存储
 */

const logger = require('../utils/logger')

class ClaudeCodeHeadersService {
  constructor() {
    this.defaultHeaders = {
      'x-stainless-retry-count': '0',
      'x-stainless-timeout': '600',
      'x-stainless-lang': 'js',
      'x-stainless-package-version': '0.70.0',
      'x-stainless-os': 'Linux',
      'x-stainless-arch': 'x64',
      'x-stainless-runtime': 'node',
      'x-stainless-runtime-version': 'v24.3.0',
      'anthropic-dangerous-direct-browser-access': 'true',
      'x-app': 'cli',
      'user-agent': 'claude-cli/2.1.7 (external, cli)',
      'accept-encoding': 'gzip, deflate, br'
    }
  }

  /**
   * 获取账号的 Claude Code headers
   * 返回平台统一的固定默认 Headers
   */
  async getAccountHeaders(accountId) {
    logger.debug(`📋 Using platform default Headers for account ${accountId}`)
    return this.defaultHeaders
  }
}

module.exports = new ClaudeCodeHeadersService()
