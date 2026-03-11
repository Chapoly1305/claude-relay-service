jest.mock('../src/models/redis', () => ({
  getClientSafe: jest.fn(),
  getAllIdsByIndex: jest.fn(),
  batchHgetallChunked: jest.fn()
}))

jest.mock('../src/utils/logger', () => ({
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
}))

jest.mock('../src/utils/proxyHelper', () => ({
  validateProxyConfig: jest.fn((proxy) => {
    if (!proxy) {
      return false
    }
    const port = Number.parseInt(proxy.port, 10)
    return ['http', 'https', 'socks5'].includes(proxy.type) && !!proxy.host && port > 0
  })
}))

const redis = require('../src/models/redis')
const globalProxyPoolServiceModule = require('../src/services/globalProxyPoolService')

const { GlobalProxyPoolService, parseProxyLine } = globalProxyPoolServiceModule

describe('GlobalProxyPoolService', () => {
  let service
  let mockClient

  beforeEach(() => {
    service = new GlobalProxyPoolService()
    mockClient = {
      get: jest.fn(),
      hset: jest.fn()
    }

    redis.getClientSafe.mockReturnValue(mockClient)
    redis.getAllIdsByIndex.mockResolvedValue([])
    redis.batchHgetallChunked.mockResolvedValue([])
    jest.clearAllMocks()
  })

  it('parses proxy URL lines', () => {
    expect(parseProxyLine('socks5://user:pass@127.0.0.1:1080')).toEqual({
      type: 'socks5',
      host: '127.0.0.1',
      port: 1080,
      username: 'user',
      password: 'pass'
    })
  })

  it('normalizes mixed proxy list entries', () => {
    const result = service.normalizeConfig({
      enabled: true,
      autoAssignOnCreate: false,
      proxies: [
        'http://127.0.0.1:8080',
        { type: 'socks5', host: '10.0.0.2', port: '1081', username: '', password: '' },
        'invalid-entry'
      ]
    })

    expect(result).toEqual({
      enabled: true,
      autoAssignOnCreate: false,
      proxies: [
        { type: 'http', host: '127.0.0.1', port: 8080, username: '', password: '' },
        { type: 'socks5', host: '10.0.0.2', port: 1081, username: '', password: '' }
      ],
      updatedAt: null
    })
  })

  it('batch assigns proxies to accounts without proxy', async () => {
    jest.spyOn(service, 'getConfig').mockResolvedValue({
      enabled: true,
      autoAssignOnCreate: true,
      proxies: [{ type: 'http', host: '127.0.0.1', port: 8080, username: '', password: '' }],
      updatedAt: null
    })

    redis.getAllIdsByIndex.mockImplementation(async (indexKey) =>
      indexKey === 'claude:account:index' ? ['acct-1'] : []
    )
    redis.batchHgetallChunked.mockResolvedValue([{ id: 'acct-1', proxy: '' }])

    const result = await service.assignMissingProxiesToAllAccounts()

    expect(mockClient.hset).toHaveBeenCalledWith(
      'claude:account:acct-1',
      'proxy',
      JSON.stringify({
        type: 'http',
        host: '127.0.0.1',
        port: 8080,
        username: '',
        password: ''
      })
    )
    expect(result.assignedCount).toBe(1)
    expect(result.accountsByPlatform.claude.assigned).toBe(1)
  })
})
