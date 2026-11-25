const express = require('express');
const authRoutes = require('./routes/auth');

const app = express();


app.use(express.json());


app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      error: 'Invalid JSON payload'
    });
  }
  next();
});


app.get('/', (req, res) => {
  res.status(200).json({
    message: 'User Authentication System API',
    endpoints: {
      'POST /signup': 'Register a new user (requires email, password, optional name)',
      'POST /login': 'Login with email and password to receive JWT',
      'GET /me': 'Get current user profile (requires Bearer token)',
      'GET /dashboard': 'User dashboard with personalized welcome message (requires Bearer token)'
    }
  });
});


app.use('/', authRoutes);

module.exports = app;
