const assert = require('assert');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../app');
const { prisma } = require('../db/config');

async function runTests() {
  console.log('\n--- Running Authentication System Tests ---\n');

  try {
    // 0. Clean database before running tests
    await prisma.user.deleteMany({});
    console.log('✓ Test database cleaned.');

    // ==========================================
    // Test Group 1: Registration (POST /signup)
    // ==========================================
    console.log('\nTesting POST /signup...');

    // 1.1 Success: Register new user
    const res1 = await request(app)
      .post('/signup')
      .send({
        email: 'john.doe@example.com',
        password: 'password123',
        name: 'John Doe'
      });
    assert.strictEqual(res1.status, 201, 'Should return 201 Created');
    assert.ok(res1.body.token, 'Should return a JWT token');
    assert.strictEqual(res1.body.user.email, 'john.doe@example.com');
    assert.strictEqual(res1.body.user.name, 'John Doe');
    assert.ok(res1.body.user.id, 'Should have user ID');
    assert.ok(res1.body.user.createdAt, 'Should have createdAt timestamp');
    assert.strictEqual(res1.body.user.password, undefined, 'Password must not be returned');
    console.log('✓ 1.1: Registration successful with valid inputs (201 Created)');

    // 1.2 Verify JWT contains id, email, jti, exp ~1h
    const decodedToken = jwt.verify(res1.body.token, process.env.JWTSECRET);
    assert.strictEqual(decodedToken.id, res1.body.user.id);
    assert.strictEqual(decodedToken.email, 'john.doe@example.com');
    assert.ok(decodedToken.jti, 'JWT must contain a unique jti identifier');
    assert.ok(decodedToken.exp - decodedToken.iat <= 3600, 'JWT expiry must be 1 hour');
    console.log('✓ 1.2: JWT contains id, email, unique jti, and 1h expiration');

    // 1.3 Normalization: Email trimmed and converted to lowercase
    const resNorm = await request(app)
      .post('/signup')
      .send({
        email: '  Jane.Smith@Domain.COM  ',
        password: 'securePassword678'
      });
    assert.strictEqual(resNorm.status, 201, 'Should normalize and create user (201 Created)');
    assert.strictEqual(resNorm.body.user.email, 'jane.smith@domain.com', 'Email must be normalized to lowercase and trimmed');
    console.log('✓ 1.3: Email normalized (trimmed and lowercased)');

    // 1.4 Error 409 Conflict: Duplicate email
    const resDup = await request(app)
      .post('/signup')
      .send({
        email: 'john.doe@example.com',
        password: 'anotherPassword123'
      });
    assert.strictEqual(resDup.status, 409, 'Should return 409 Conflict for duplicate email');
    assert.strictEqual(resDup.body.error, 'Email already exists');
    console.log('✓ 1.4: Duplicate email rejected (409 Conflict)');

    // 1.5 Error 400 Bad Request: Password shorter than 6 characters
    const resShortPass = await request(app)
      .post('/signup')
      .send({
        email: 'shortpass@example.com',
        password: '123'
      });
    assert.strictEqual(resShortPass.status, 400, 'Should return 400 Bad Request for short password');
    console.log('✓ 1.5: Short password (<6 chars) rejected (400 Bad Request)');

    // 1.6 Error 400 Bad Request: Missing or invalid inputs
    const resMissingEmail = await request(app)
      .post('/signup')
      .send({ password: 'validPassword123' });
    assert.strictEqual(resMissingEmail.status, 400, 'Missing email should return 400');

    const resInvalidEmail = await request(app)
      .post('/signup')
      .send({ email: 'not-an-email', password: 'validPassword123' });
    assert.strictEqual(resInvalidEmail.status, 400, 'Invalid email format should return 400');
    console.log('✓ 1.6: Missing/invalid input rejected (400 Bad Request)');

    // ==========================================
    // Test Group 2: Login (POST /login)
    // ==========================================
    console.log('\nTesting POST /login...');

    // 2.1 Success: Login with correct credentials
    const resLogin = await request(app)
      .post('/login')
      .send({
        email: 'john.doe@example.com',
        password: 'password123'
      });
    assert.strictEqual(resLogin.status, 200, 'Should return 200 OK on valid login');
    assert.ok(resLogin.body.token, 'Should return JWT token');
    assert.strictEqual(resLogin.body.user.email, 'john.doe@example.com');
    assert.strictEqual(resLogin.body.user.password, undefined, 'Password must not be returned');
    const validToken = resLogin.body.token;
    console.log('✓ 2.1: Login successful (200 OK)');

    // 2.2 Success: Login with email having different casing / whitespace
    const resLoginNorm = await request(app)
      .post('/login')
      .send({
        email: '  JOHN.DOE@EXAMPLE.COM  ',
        password: 'password123'
      });
    assert.strictEqual(resLoginNorm.status, 200, 'Normalized email login should succeed');
    console.log('✓ 2.2: Login with case/whitespace normalized email (200 OK)');

    // 2.3 Error 401 Unauthorized: Unknown email
    const resUnknownEmail = await request(app)
      .post('/login')
      .send({
        email: 'nonexistent@example.com',
        password: 'password123'
      });
    assert.strictEqual(resUnknownEmail.status, 401, 'Should return 401 Unauthorized');
    assert.strictEqual(resUnknownEmail.body.error, 'Invalid email or password');

    // 2.4 Error 401 Unauthorized: Incorrect password (same error message as unknown email)
    const resWrongPass = await request(app)
      .post('/login')
      .send({
        email: 'john.doe@example.com',
        password: 'wrongPassword123'
      });
    assert.strictEqual(resWrongPass.status, 401, 'Should return 401 Unauthorized');
    assert.strictEqual(resWrongPass.body.error, 'Invalid email or password');
    assert.strictEqual(resUnknownEmail.body.error, resWrongPass.body.error, 'Error message must match for both unknown email and bad password');
    console.log('✓ 2.3 & 2.4: Unknown email and incorrect password return same 401 error message');

    // 2.5 Error 400 Bad Request: Missing or invalid fields
    const resMissingLoginFields = await request(app)
      .post('/login')
      .send({ email: 'john.doe@example.com' });
    assert.strictEqual(resMissingLoginFields.status, 400, 'Missing password should return 400');
    console.log('✓ 2.5: Missing input fields return 400 Bad Request');

    // ==========================================
    // Test Group 3: JWT Middleware (requireAuth)
    // ==========================================
    console.log('\nTesting requireAuth Middleware...');

    // 3.1 Missing Authorization header
    const resNoAuth = await request(app).get('/me');
    assert.strictEqual(resNoAuth.status, 401, 'Missing token should return 401');

    // 3.2 Malformed Authorization header
    const resMalformedAuth = await request(app)
      .get('/me')
      .set('Authorization', 'InvalidFormatHeader');
    assert.strictEqual(resMalformedAuth.status, 401, 'Malformed auth header should return 401');

    // 3.3 Invalid/tampered token
    const resTampered = await request(app)
      .get('/me')
      .set('Authorization', 'Bearer invalid.tampered.token');
    assert.strictEqual(resTampered.status, 401, 'Invalid token should return 401');

    // 3.4 Expired token
    const expiredToken = jwt.sign(
      { id: 999, email: 'expired@example.com' },
      process.env.JWTSECRET,
      { expiresIn: '-1s' }
    );
    const resExpired = await request(app)
      .get('/me')
      .set('Authorization', `Bearer ${expiredToken}`);
    assert.strictEqual(resExpired.status, 401, 'Expired token should return 401');
    console.log('✓ 3.1 - 3.4: All invalid/missing/expired token scenarios rejected with 401');

    // ==========================================
    // Test Group 4: Get User Profile (GET /me)
    // ==========================================
    console.log('\nTesting GET /me...');

    // 4.1 Success: Get profile with valid token
    const resMe = await request(app)
      .get('/me')
      .set('Authorization', `Bearer ${validToken}`);
    assert.strictEqual(resMe.status, 200, 'Should return 200 OK');
    assert.strictEqual(resMe.body.user.email, 'john.doe@example.com');
    assert.strictEqual(resMe.body.user.name, 'John Doe');
    assert.ok(resMe.body.user.id);
    assert.ok(resMe.body.user.createdAt);
    assert.strictEqual(resMe.body.user.password, undefined, 'Password must never be returned');
    console.log('✓ 4.1: Profile retrieved successfully without password (200 OK)');

    // 4.2 Error 404 Not Found: User deleted from DB but has valid signed token
    const ghostToken = jwt.sign(
      { id: 999999, email: 'ghost@example.com' },
      process.env.JWTSECRET,
      { expiresIn: '1h' }
    );
    const resGhostMe = await request(app)
      .get('/me')
      .set('Authorization', `Bearer ${ghostToken}`);
    assert.strictEqual(resGhostMe.status, 404, 'Non-existent user should return 404');
    console.log('✓ 4.2: Deleted / non-existent user returns 404 Not Found');

    // ==========================================
    // Test Group 5: User Dashboard (GET /dashboard)
    // ==========================================
    console.log('\nTesting GET /dashboard...');

    // 5.1 Success with name: returns "Welcome, <name>!"
    const resDashName = await request(app)
      .get('/dashboard')
      .set('Authorization', `Bearer ${validToken}`);
    assert.strictEqual(resDashName.status, 200, 'Should return 200 OK');
    assert.strictEqual(resDashName.body.message, 'Welcome, John Doe!');
    console.log('✓ 5.1: Dashboard welcome message uses user\'s name when available');

    // 5.2 Success without name: returns "Welcome, <email>!"
    const tokenNoName = resNorm.body.token; // Jane Smith was registered without name
    const resDashEmail = await request(app)
      .get('/dashboard')
      .set('Authorization', `Bearer ${tokenNoName}`);
    assert.strictEqual(resDashEmail.status, 200, 'Should return 200 OK');
    assert.strictEqual(resDashEmail.body.message, 'Welcome, jane.smith@domain.com!');
    console.log('✓ 5.2: Dashboard welcome message falls back to email when name is null/empty');

    // 5.3 Error 404 Not Found on dashboard for non-existent user
    const resGhostDash = await request(app)
      .get('/dashboard')
      .set('Authorization', `Bearer ${ghostToken}`);
    assert.strictEqual(resGhostDash.status, 404, 'Non-existent user on dashboard should return 404');
    console.log('✓ 5.3: Non-existent user returns 404 Not Found on dashboard');

    console.log('\n==========================================');
    console.log('ALL TESTS PASSED SUCCESSFULLY! (100% PASS)');
    console.log('==========================================\n');
  } catch (error) {
    console.error('\n❌ Test Failure:', error);
    process.exitCode = 1;
  } finally {
    await prisma.$disconnect();
  }
}

runTests();
