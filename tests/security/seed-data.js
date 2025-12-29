/**
 * Test Data Seeding Script for Claude Relay Fuzzing
 *
 * Populates Redis with test data for authentication bypass regression testing.
 *
 * Test Sessions:
 * - valid_admin_token: Complete valid session (baseline)
 * - empty_session_token: Empty object {} (should fail)
 * - missing_username_token: Session without username (CVE-1 test)
 * - missing_logintime_token: Session without loginTime (CVE-1 test)
 * - random_field_token: {foo: 'bar'} (CVE-1 critical case)
 * - expired_session_token: Expired session (25h old)
 * - partial_adminid_token: Missing adminId
 * - null_values_token: With null values for required fields
 *
 * Run: node tests/security/seed-data.js
 */

const redis = require('redis');

// Configuration
const REDIS_CONFIG = {
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  db: parseInt(process.env.REDIS_DB) || 0,
  retryStrategy: () => null
};

const EXPIRY_TIME = 3600; // 1 hour in seconds

async function main() {
  console.log('🧪 Seeding test data into Redis...');
  console.log(`   Host: ${REDIS_CONFIG.host}:${REDIS_CONFIG.port}`);
  console.log('');

  let client;
  try {
    // Connect to Redis
    client = redis.createClient(REDIS_CONFIG);

    client.on('error', (err) => {
      console.error('❌ Redis error:', err.message);
      process.exit(1);
    });

    // Wait for connection
    await client.connect();
    console.log('✓ Connected to Redis');
    console.log('');

    // Seed admin sessions
    await seedAdminSessions(client);

    // Seed API keys
    await seedApiKeys(client);

    // Seed user accounts
    await seedUserAccounts(client);

    console.log('');
    console.log('✅ Test data seeding complete!');
    console.log('');
    console.log('📝 Test Sessions Created:');
    console.log('   valid_admin_token - Complete valid session');
    console.log('   empty_session_token - Empty object (should fail)');
    console.log('   missing_username_token - Missing username field');
    console.log('   missing_logintime_token - Missing loginTime field');
    console.log('   random_field_token - {foo: "bar"} (CVE-1 test)');
    console.log('   expired_session_token - Expired (25h old)');
    console.log('   partial_adminid_token - Missing adminId');
    console.log('   null_values_token - Null required fields');
    console.log('');
    console.log('Endpoints to test:');
    console.log('   GET /users/ - authenticateUserOrAdmin');
    console.log('   GET /users/stats/overview - authenticateUserOrAdmin');
    console.log('   GET /admin/webhook/config - authenticateUserOrAdmin');
    console.log('   GET /admin/api-keys - authenticateUserOrAdmin');
    console.log('');
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exit(1);
  } finally {
    if (client) {
      await client.quit();
    }
  }
}

/**
 * Seed admin sessions with various test cases
 */
async function seedAdminSessions(client) {
  console.log('🔐 Seeding admin sessions...');

  const now = new Date();
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const twoWeeksAgo = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);

  const sessions = [
    {
      token: 'valid_admin_token',
      data: {
        username: 'test_admin',
        adminId: 'admin_123',
        loginTime: now.toISOString(),
        lastActivity: now.toISOString()
      },
      description: 'Valid complete session (SHOULD PASS)'
    },
    {
      token: 'empty_session_token',
      data: {},
      description: 'Empty object (SHOULD FAIL - no fields)'
    },
    {
      token: 'missing_username_token',
      data: {
        adminId: 'admin_456',
        loginTime: now.toISOString(),
        lastActivity: now.toISOString()
        // Missing: username
      },
      description: 'Missing username field (SHOULD FAIL - CVE-1)'
    },
    {
      token: 'missing_logintime_token',
      data: {
        username: 'admin_user',
        adminId: 'admin_789',
        lastActivity: now.toISOString()
        // Missing: loginTime
      },
      description: 'Missing loginTime field (SHOULD FAIL - CVE-1)'
    },
    {
      token: 'random_field_token',
      data: {
        foo: 'bar'
        // Missing: username, loginTime, adminId - CVE-1 critical case
      },
      description: 'Random field only (SHOULD FAIL - CVE-1 critical test)'
    },
    {
      token: 'expired_session_token',
      data: {
        username: 'expired_user',
        adminId: 'admin_expired',
        loginTime: twoWeeksAgo.toISOString(),
        lastActivity: twoWeeksAgo.toISOString()
      },
      description: 'Expired session (25h+ old) (SHOULD FAIL - inactivity timeout)'
    },
    {
      token: 'partial_adminid_token',
      data: {
        username: 'partial_admin',
        loginTime: now.toISOString(),
        lastActivity: now.toISOString()
        // Missing: adminId (should default to 'admin' or generate ID)
      },
      description: 'Missing adminId field'
    },
    {
      token: 'null_values_token',
      data: {
        username: null,
        loginTime: null,
        adminId: 'admin_null'
      },
      description: 'Null values for required fields (SHOULD FAIL)'
    }
  ];

  for (const session of sessions) {
    // Use HSET to store hash (matching Redis.setSession behavior)
    await client.hSet(`session:${session.token}`, session.data);

    // Set expiry
    await client.expire(`session:${session.token}`, EXPIRY_TIME);

    console.log(`   ✓ ${session.token}`);
    console.log(`     → ${session.description}`);
  }

  console.log(`   Total sessions seeded: ${sessions.length}`);
}

/**
 * Seed test API keys
 */
async function seedApiKeys(client) {
  console.log('');
  console.log('🔑 Seeding API keys...');

  const keys = [
    {
      id: 'test_key_001',
      hash: 'abc123def456',
      data: {
        keyId: 'test_key_001',
        name: 'Test Key - Full Permissions',
        hash: 'abc123def456',
        permissions: 'all',
        active: true,
        createdAt: new Date().toISOString()
      },
      description: 'Full permissions API key'
    },
    {
      id: 'test_key_002',
      hash: 'xyz789uvw000',
      data: {
        keyId: 'test_key_002',
        name: 'Test Key - Expired',
        hash: 'xyz789uvw000',
        permissions: 'all',
        active: false,
        expiresAt: new Date(Date.now() - 1000).toISOString(),
        createdAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      description: 'Expired API key'
    }
  ];

  for (const key of keys) {
    await client.hSet(`api_key:${key.id}`, key.data);
    await client.expire(`api_key:${key.id}`, EXPIRY_TIME);

    console.log(`   ✓ ${key.id}`);
    console.log(`     → ${key.description}`);
  }

  console.log(`   Total API keys seeded: ${keys.length}`);
}

/**
 * Seed test user accounts
 */
async function seedUserAccounts(client) {
  console.log('');
  console.log('👤 Seeding user accounts...');

  const users = [
    {
      id: 'user_001',
      data: {
        userId: 'user_001',
        username: 'testuser',
        email: 'testuser@test.local',
        isActive: true,
        createdAt: new Date().toISOString()
      },
      description: 'Active test user'
    },
    {
      id: 'user_002',
      data: {
        userId: 'user_002',
        username: 'disableduser',
        email: 'disabled@test.local',
        isActive: false,
        createdAt: new Date().toISOString()
      },
      description: 'Disabled test user'
    }
  ];

  for (const user of users) {
    await client.hSet(`user:${user.id}`, user.data);
    await client.expire(`user:${user.id}`, EXPIRY_TIME);

    console.log(`   ✓ ${user.id}`);
    console.log(`     → ${user.description}`);
  }

  console.log(`   Total users seeded: ${users.length}`);
}

// Run if executed directly
if (require.main === module) {
  main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
}

module.exports = {
  seedAdminSessions,
  seedApiKeys,
  seedUserAccounts
};
