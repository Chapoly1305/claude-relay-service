#!/usr/bin/env node

const fs = require('fs').promises
const path = require('path')
const dotenv = require('dotenv')

dotenv.config({ path: path.join(__dirname, '..', '.env') })

function parseArgs(argv) {
  const options = {
    inputPath: '',
    dryRun: false
  }

  for (const arg of argv) {
    if (arg === '--dry-run') {
      options.dryRun = true
      continue
    }

    if (arg.startsWith('--path=')) {
      options.inputPath = arg.slice('--path='.length).trim()
      continue
    }

    if (!arg.startsWith('--') && !options.inputPath) {
      options.inputPath = arg.trim()
    }
  }

  return options
}

async function pathExists(targetPath) {
  try {
    await fs.access(targetPath)
    return true
  } catch {
    return false
  }
}

async function collectJsonFiles(inputPath) {
  const resolvedPath = path.resolve(inputPath)
  const stat = await fs.stat(resolvedPath)

  if (stat.isFile()) {
    return resolvedPath.toLowerCase().endsWith('.json') ? [resolvedPath] : []
  }

  if (!stat.isDirectory()) {
    return []
  }

  const results = []

  async function walk(currentPath) {
    const entries = await fs.readdir(currentPath, { withFileTypes: true })

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name)

      if (entry.isDirectory()) {
        await walk(fullPath)
        continue
      }

      if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) {
        results.push(fullPath)
      }
    }
  }

  await walk(resolvedPath)
  results.sort((left, right) => left.localeCompare(right))
  return results
}

function decodeJwtPayload(token) {
  if (!token || typeof token !== 'string') {
    return null
  }

  const parts = token.split('.')
  if (parts.length < 2) {
    return null
  }

  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  } catch {
    return null
  }
}

function normalizeString(value) {
  return typeof value === 'string' ? value.trim() : ''
}

function normalizeBooleanString(value) {
  if (value === true) {
    return true
  }
  if (value === false) {
    return false
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase()
    if (normalized === 'true') {
      return true
    }
    if (normalized === 'false') {
      return false
    }
  }
  return false
}

function toIsoOrNull(value) {
  const text = normalizeString(value)
  if (!text) {
    return null
  }

  const timestamp = Date.parse(text)
  return Number.isNaN(timestamp) ? null : new Date(timestamp).toISOString()
}

function buildImportPayload(raw, sourceFile) {
  const idToken = normalizeString(raw.id_token || raw.idToken)
  const accessToken = normalizeString(raw.access_token || raw.accessToken)
  const refreshToken = normalizeString(raw.refresh_token || raw.refreshToken)

  if (!refreshToken) {
    throw new Error('missing refresh token')
  }

  const idPayload = decodeJwtPayload(idToken) || {}
  const accessPayload = decodeJwtPayload(accessToken) || {}
  const authClaims = idPayload['https://api.openai.com/auth'] || accessPayload['https://api.openai.com/auth'] || {}
  const profileClaims =
    accessPayload['https://api.openai.com/profile'] || idPayload['https://api.openai.com/profile'] || {}

  const organizations = Array.isArray(authClaims.organizations) ? authClaims.organizations : []
  const defaultOrg = organizations.find((org) => org && org.is_default) || organizations[0] || {}

  const email = normalizeString(raw.email || raw.mailtm_email || idPayload.email || profileClaims.email)
  if (!email) {
    throw new Error('missing email')
  }

  const accountInfo = {
    accountId: normalizeString(raw.account_id || authClaims.chatgpt_account_id),
    chatgptUserId: normalizeString(authClaims.chatgpt_user_id || authClaims.user_id || idPayload.sub),
    organizationId: normalizeString(defaultOrg.id),
    organizationRole: normalizeString(defaultOrg.role),
    organizationTitle: normalizeString(defaultOrg.title),
    planType: normalizeString(raw.plan_type || authClaims.chatgpt_plan_type),
    email,
    emailVerified:
      normalizeBooleanString(raw.email_verified) ||
      normalizeBooleanString(idPayload.email_verified) ||
      normalizeBooleanString(profileClaims.email_verified)
  }

  const openaiOauth = {
    idToken,
    accessToken,
    refreshToken,
    accountId: accountInfo.accountId,
    email,
    lastRefresh: normalizeString(raw.last_refresh || raw.lastRefresh),
    expiresAt: normalizeString(raw.expired || raw.expiresAt),
    importedFrom: sourceFile,
    importedAt: new Date().toISOString()
  }

  return {
    email,
    accountData: {
      name: email,
      description: `Imported from ${path.basename(sourceFile)}`,
      accountType: 'shared',
      priority: 50,
      rateLimitDuration: 60,
      openaiOauth,
      accountInfo,
      isActive: true,
      schedulable: true,
      subscriptionExpiresAt: toIsoOrNull(raw.expired || raw.expiresAt)
    }
  }
}

async function main() {
  const { inputPath, dryRun } = parseArgs(process.argv.slice(2))

  if (!inputPath) {
    console.error('Usage: node scripts/import-openai-oauth-json.js <path> [--dry-run]')
    console.error('   or: node scripts/import-openai-oauth-json.js --path=/path/to/jsons [--dry-run]')
    process.exit(1)
  }

  const configPath = path.join(__dirname, '..', 'config', 'config.js')
  if (!(await pathExists(configPath))) {
    console.error('Missing config/config.js')
    console.error('Copy config/config.example.js to config/config.js before running this script.')
    process.exit(1)
  }

  const redis = require('../src/models/redis')
  const openaiAccountService = require('../src/services/account/openaiAccountService')
  const logger = require('../src/utils/logger')

  try {
    const files = await collectJsonFiles(inputPath)
    if (files.length === 0) {
      console.error(`No .json files found under: ${path.resolve(inputPath)}`)
      process.exit(1)
    }

    logger.info(`Found ${files.length} JSON file(s) to inspect`)
    if (dryRun) {
      logger.info('Running in dry-run mode, no data will be written')
    }

    await redis.connect()
    logger.success('Connected to Redis')

    const existingAccounts = await openaiAccountService.getAllAccounts()
    const existingEmails = new Set(
      existingAccounts
        .map((account) => normalizeString(account.email).toLowerCase())
        .filter(Boolean)
    )
    const batchEmails = new Set()

    const stats = {
      discovered: files.length,
      imported: 0,
      skippedExisting: 0,
      skippedDuplicateInBatch: 0,
      failed: 0
    }

    for (const file of files) {
      try {
        const rawContent = await fs.readFile(file, 'utf8')
        const rawData = JSON.parse(rawContent)
        const { email, accountData } = buildImportPayload(rawData, file)
        const emailKey = email.toLowerCase()

        if (existingEmails.has(emailKey)) {
          stats.skippedExisting++
          logger.info(`Skip existing account: ${email}`)
          continue
        }

        if (batchEmails.has(emailKey)) {
          stats.skippedDuplicateInBatch++
          logger.info(`Skip duplicate email in current batch: ${email}`)
          continue
        }

        if (dryRun) {
          stats.imported++
          existingEmails.add(emailKey)
          batchEmails.add(emailKey)
          logger.info(`[dry-run] Would import account: ${email}`)
          continue
        }

        await openaiAccountService.createAccount(accountData)
        existingEmails.add(emailKey)
        batchEmails.add(emailKey)
        stats.imported++
        logger.success(`Imported account: ${email}`)
      } catch (error) {
        const message = normalizeString(error.message)
        if (message === 'missing email' || message === 'missing refresh token') {
          stats.failed++
          logger.warn(`Skip invalid JSON ${file}: ${message}`)
          continue
        }
        stats.failed++
        logger.error(`Failed to import ${file}:`, error)
      }
    }

    logger.info('Import finished', stats)
  } catch (error) {
    console.error(error.message || error)
    process.exitCode = 1
  } finally {
    try {
      const redis = require('../src/models/redis')
      await redis.disconnect()
    } catch {}
  }
}

main()
