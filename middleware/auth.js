const jwt = require('jsonwebtoken');



function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];

  if (!authHeader) {
    return res.status(401).json({
      error: 'Access denied. Authorization header is missing.'
    });
  }


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

  try {
    const decoded = jwt.verify(token, secret);

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
