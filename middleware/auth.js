const jwt = require('jsonwebtoken');

/**
 * Middleware: requireAuth
 * 
 * Verifies the JSON Web Token from the Authorization header:
 * Expected Header Format: "Authorization: Bearer <token>"
 * 
 * - If valid: decodes the payload, attaches it to `req.user`, and calls `next()`
 * - If missing, invalid, or expired: returns 401 Unauthorized
 */
function requireAuth(req, res, next) {
  // 1. Read Authorization header
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];

  if (!authHeader) {
    return res.status(401).json({
      error: 'Access denied. Authorization header is missing.'
    });
  }

  // 2. Validate format: "Bearer <token>"
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({
      error: 'Invalid token format. Format should be: Bearer <token>'
    });
  }

  const token = parts[1];
  const secret = process.env.JWTSECRET;

  if (!secret) {
    return res.status(500).json({
      error: 'Internal Server Error: JWTSECRET environment variable is missing.'
    });
  }

  // 3. Verify token with JWT secret
  try {
    const decoded = jwt.verify(token, secret);
    // Attach decoded token payload (id, email, etc.) to req.user
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token has expired. Please log in again.'
      });
    }

    return res.status(401).json({
      error: 'Invalid or malformed token.'
    });
  }
}

module.exports = { requireAuth };
