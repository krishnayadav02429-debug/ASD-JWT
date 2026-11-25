const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { prisma } = require('../db/config');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

/**
 * Helper: Generate a JWT token containing user id and email.
 * Includes a unique JWT ID (jti) using crypto.randomUUID().
 * Expires in 1 hour.
 */
function generateToken(user) {
  const jti = crypto.randomUUID();

  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    process.env.JWTSECRET,
    {
      expiresIn: '1h',
      jwtid: jti
    }
  );
}

/**
 * Helper: Basic email format check.
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// ==========================================
// 1. User Registration – POST /signup
// ==========================================
router.post('/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Validate email
    if (!email || typeof email !== 'string') {
      return res.status(400).json({
        error: 'Email is required and must be a string'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        error: 'Please provide a valid email address'
      });
    }

    // Validate password
    if (!password || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Password is required and must be a string'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Password must contain at least 6 characters'
      });
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    if (existingUser) {
      return res.status(409).json({
        error: 'Email already exists'
      });
    }

    // Hash password using bcrypt with 10 salt rounds
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user in database
    const newUser = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        name: typeof name === 'string' && name.trim() ? name.trim() : null
      }
    });

    // Generate JWT token
    const token = generateToken(newUser);

    // Return 201 Created with user details (excluding password) and JWT
    return res.status(201).json({
      message: 'Registration successful',
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        createdAt: newUser.createdAt
      },
      token
    });
  } catch (error) {
    console.error('Error during signup:', error);
    return res.status(500).json({
      error: 'An internal server error occurred during registration'
    });
  }
});

// ==========================================
// 2. User Login – POST /login
// ==========================================
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate that both fields are provided as strings
    if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Email and password are required and must be strings'
      });
    }

    // Normalize email before searching database
    const normalizedEmail = email.trim().toLowerCase();

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    // Verify password if user exists
    let isPasswordValid = false;
    if (user) {
      isPasswordValid = await bcrypt.compare(password, user.password);
    }

    // Return the SAME error message for an unknown email and an incorrect password
    if (!user || !isPasswordValid) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    // Generate JWT token
    const token = generateToken(user);

    // Return 200 OK with basic user details and JWT
    return res.status(200).json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt
      },
      token
    });
  } catch (error) {
    console.error('Error during login:', error);
    return res.status(500).json({
      error: 'An internal server error occurred during login'
    });
  }
});

// ==========================================
// 4. Get User Profile – GET /me (Protected)
// ==========================================
router.get('/me', requireAuth, async (req, res) => {
  try {
    // Fetch user details using the ID from the decoded JWT payload
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true
      }
    });

    // If user does not exist
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    // Return user details without password
    return res.status(200).json({
      user
    });
  } catch (error) {
    console.error('Error in /me:', error);
    return res.status(500).json({
      error: 'An internal server error occurred while retrieving user profile'
    });
  }
});

// ==========================================
// 5. User Dashboard – GET /dashboard (Protected)
// ==========================================
router.get('/dashboard', requireAuth, async (req, res) => {
  try {
    // Fetch authenticated user's email and name
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        email: true,
        name: true
      }
    });

    // If user does not exist
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    // If name is available, use name; otherwise, use email
    const displayName = user.name && user.name.trim() ? user.name.trim() : user.email;

    return res.status(200).json({
      message: `Welcome, ${displayName}!`,
      user: {
        email: user.email,
        name: user.name
      }
    });
  } catch (error) {
    console.error('Error in /dashboard:', error);
    return res.status(500).json({
      error: 'An internal server error occurred while retrieving user dashboard'
    });
  }
});

module.exports = router;
