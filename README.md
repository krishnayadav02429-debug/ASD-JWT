# User Authentication System Using JWT

A user authentication and authorization REST API built with **Node.js**, **Express.js**, **Prisma ORM (Prisma 7 with PostgreSQL adapter)**, **PostgreSQL**, **bcrypt**, and **JSON Web Tokens (JWT)**.

---

## 📌 Features

- **User Registration (`POST /signup`)**:
  - Validates email format and password length (minimum 6 characters).
  - Normalizes email addresses (trims whitespace and converts to lowercase).
  - Rejects duplicate email registrations (`409 Conflict`).
  - Hashes passwords securely using **bcrypt** with 10 salt rounds.
  - Automatically signs and returns a JWT token upon successful registration (`201 Created`).

- **User Login (`POST /login`)**:
  - Normalizes email before database lookup.
  - Verifies credentials against the bcrypt password hash.
  - Returns the exact same error message (`"Invalid email or password"`) for non-existent emails and incorrect passwords (`401 Unauthorized`) to prevent user enumeration attacks.
  - Returns user details and a new JWT token (`200 OK`).

- **JWT Authentication Middleware (`requireAuth`)**:
  - Reads token from `Authorization: Bearer <token>` header.
  - Verifies token signature using `JWTSECRET` and checks expiration (1-hour lifespan).
  - Uses `crypto.randomUUID()` to generate unique JWT IDs (`jti`).
  - Attaches decoded user payload to `req.user`.
  - Rejects missing, malformed, or expired tokens with `401 Unauthorized`.

- **User Profile (`GET /me`)**:
  - Protected endpoint retrieving authenticated user profile.
  - Returns user's `id`, `email`, `name`, and `createdAt`.
  - Never returns the user password or password hash.

- **User Dashboard (`GET /dashboard`)**:
  - Protected endpoint returning a personalized welcome message.
  - Uses the user's `name` if available (`Welcome, <name>!`), or falls back to `email` (`Welcome, <email>!`).

---

## 🏗️ Project Architecture & File Structure

```text
├── db/
│   └── config.js              # Prisma 7 client initialized with @prisma/adapter-pg
├── middleware/
│   └── auth.js                # requireAuth JWT authentication middleware
├── prisma/
│   ├── migrations/            # SQL migration history
│   └── schema.prisma          # Prisma schema with User model
├── routes/
│   └── auth.js                # Auth routes (/signup, /login, /me, /dashboard)
├── test/
│   └── auth.test.js           # Automated end-to-end test suite
├── .env.example               # Example environment variable template
├── .gitignore                 # Git ignore file (ignores node_modules, .env)
├── app.js                     # Express application configuration
├── package.json               # Dependencies and scripts
├── prisma7.config.js          # Prisma 7 configuration file
├── README.md                  # Complete documentation
└── server.js                  # Application entry point
```

---

## 🗄️ Database Model (Prisma Schema)

Located at `prisma/schema.prisma`:

```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
}

model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  password  String
  name      String?
  createdAt DateTime @default(now())
}
```

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory (based on `.env.example`):

```env
# PostgreSQL connection string
DATABASE_URL="postgresql://postgres:password@localhost:5432/jwt_auth_db"

# JWT Secret Key
JWTSECRET="your_secret_jwt_key_here"

# Server Port
PORT=3000
```

---

## 🚀 Getting Started

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Database & Apply Migrations
Ensure PostgreSQL is running, then run:
```bash
npx prisma migrate dev --name init
```

### 3. Generate Prisma Client
```bash
npx prisma generate
```

### 4. Start the Application
- **Production mode:**
  ```bash
  npm start
  ```
- **Development mode (with auto-reload):**
  ```bash
  npm run dev
  ```
The server will start on `http://localhost:3000`.

---

## 🧪 Running Automated Tests

Run the complete test suite verifying all 5 endpoints, edge cases, error codes, and middleware:

```bash
npm test
```

Expected output:
```text
✓ Test database cleaned.
✓ 1.1: Registration successful with valid inputs (201 Created)
✓ 1.2: JWT contains id, email, unique jti, and 1h expiration
✓ 1.3: Email normalized (trimmed and lowercased)
✓ 1.4: Duplicate email rejected (409 Conflict)
✓ 1.5: Short password (<6 chars) rejected (400 Bad Request)
✓ 1.6: Missing/invalid input rejected (400 Bad Request)
✓ 2.1: Login successful (200 OK)
✓ 2.2: Login with case/whitespace normalized email (200 OK)
✓ 2.3 & 2.4: Unknown email and incorrect password return same 401 error message
✓ 2.5: Missing input fields return 400 Bad Request
✓ 3.1 - 3.4: All invalid/missing/expired token scenarios rejected with 401
✓ 4.1: Profile retrieved successfully without password (200 OK)
✓ 4.2: Deleted / non-existent user returns 404 Not Found
✓ 5.1: Dashboard welcome message uses user's name when available
✓ 5.2: Dashboard welcome message falls back to email when name is null/empty
✓ 5.3: Non-existent user returns 404 Not Found on dashboard
ALL TESTS PASSED SUCCESSFULLY! (100% PASS)
```

---

## 📖 API Documentation & Examples

### 1. Register User
**`POST /signup`**

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "mypassword123",
  "name": "Alice"
}
```

**Responses:**
- `201 Created`:
  ```json
  {
    "message": "Registration successful",
    "user": {
      "id": 1,
      "email": "user@example.com",
      "name": "Alice",
      "createdAt": "2026-11-25T06:58:50.000Z"
    },
    "token": "eyJhbGciOi..."
  }
  ```
- `400 Bad Request`: When password is shorter than 6 characters or email is invalid.
- `409 Conflict`: When email is already registered (`{"error": "Email already exists"}`).

---

### 2. User Login
**`POST /login`**

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "mypassword123"
}
```

**Responses:**
- `200 OK`:
  ```json
  {
    "message": "Login successful",
    "user": {
      "id": 1,
      "email": "user@example.com",
      "name": "Alice",
      "createdAt": "2026-11-25T06:58:50.000Z"
    },
    "token": "eyJhbGciOi..."
  }
  ```
- `400 Bad Request`: When email or password fields are missing.
- `401 Unauthorized`: When email is unknown or password is incorrect (`{"error": "Invalid email or password"}`).

---

### 3. Get User Profile (Protected)
**`GET /me`**

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Responses:**
- `200 OK`:
  ```json
  {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "name": "Alice",
      "createdAt": "2026-11-25T06:58:50.000Z"
    }
  }
  ```
- `401 Unauthorized`: If token is missing, invalid, or expired.
- `404 Not Found`: If user does not exist in the database.

---

### 4. User Dashboard (Protected)
**`GET /dashboard`**

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Responses:**
- `200 OK` (when name is set):
  ```json
  {
    "message": "Welcome, Alice!",
    "user": {
      "email": "user@example.com",
      "name": "Alice"
    }
  }
  ```
- `200 OK` (when name is empty/null):
  ```json
  {
    "message": "Welcome, user@example.com!",
    "user": {
      "email": "user@example.com",
      "name": null
    }
  }
  ```
- `401 Unauthorized`: If token is missing, invalid, or expired.
- `404 Not Found`: If user does not exist in the database.
