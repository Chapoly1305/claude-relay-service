const express = require('express')
const request = require('supertest')

jest.mock('../src/middleware/auth', () => ({
  authenticateAdmin: (req, res, next) => next()
}))

jest.mock('../src/services/account/claudeAccountService', () => ({}))
jest.mock('../src/services/account/claudeConsoleAccountService', () => ({}))
jest.mock('../src/services/account/geminiAccountService', () => ({}))
jest.mock('../src/services/account/bedrockAccountService', () => ({}))
jest.mock('../src/services/account/droidAccountService', () => ({}))
jest.mock('../src/models/redis', () => ({
  getClient: jest.fn(() => ({
    get: jest.fn(),
    set: jest.fn()
  }))
}))
jest.mock('../src/utils/logger', () => ({
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  success: jest.fn()
}))
jest.mock(
  '../config/config',
  () => ({
    web: {}
  }),
  { virtual: true }
)
jest.mock('axios', () => ({
  get: jest.fn()
}))
jest.mock('../src/services/globalProxyPoolService', () => ({
  assignMissingProxiesToAllAccounts: jest.fn(),
  getAssignmentDebugSummary: jest.fn()
}))

const globalProxyPoolService = require('../src/services/globalProxyPoolService')
const systemRouter = require('../src/routes/admin/system')

describe('global proxy pool admin routes', () => {
  const buildApp = () => {
    const app = express()
    app.use(express.json())
    app.use('/admin', systemRouter)
    return app
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('returns debug summary from the local endpoint', async () => {
    globalProxyPoolService.getAssignmentDebugSummary.mockResolvedValue({
      config: {
        enabled: true,
        autoAssignOnCreate: true,
        proxyCount: 2,
        updatedAt: '2026-03-11T00:00:00.000Z'
      },
      totalAccounts: 3,
      accountsWithProxy: 2,
      accountsWithoutProxy: 1,
      invalidRecords: 0,
      accountsByPlatform: {
        claude: {
          total: 3,
          withProxy: 2,
          withoutProxy: 1,
          invalidRecords: 0,
          samplesWithProxy: [{ id: 'acct-1' }],
          samplesWithoutProxy: [{ id: 'acct-2', rawProxy: '' }]
        }
      }
    })

    const app = buildApp()
    const response = await request(app).get('/admin/global-proxy-pool/debug?sampleSize=5')

    expect(response.status).toBe(200)
    expect(globalProxyPoolService.getAssignmentDebugSummary).toHaveBeenCalledWith(null, {
      sampleSize: '5'
    })
    expect(response.body.success).toBe(true)
    expect(response.body.data.totalAccounts).toBe(3)
  })

  it('passes the current form config into batch assignment', async () => {
    globalProxyPoolService.assignMissingProxiesToAllAccounts.mockResolvedValue({
      assignedCount: 1,
      scannedCount: 1,
      skippedCount: 0,
      accountsByPlatform: {
        claude: { assigned: 1, scanned: 1 }
      }
    })

    const payload = {
      globalProxyPool: {
        enabled: true,
        proxies: ['http://127.0.0.1:8080']
      }
    }

    const app = buildApp()
    const response = await request(app).post('/admin/global-proxy-pool/assign-missing').send(payload)

    expect(response.status).toBe(200)
    expect(globalProxyPoolService.assignMissingProxiesToAllAccounts).toHaveBeenCalledWith(
      payload.globalProxyPool
    )
    expect(response.body.data.assignedCount).toBe(1)
  })
})
