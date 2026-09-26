# Strong Auth Backend — Production API

Postman ya kisi bhi API client se test karne ke liye yeh complete guide.

---

## 🔧 Setup (Ek baar)

```bash
npm install
cp .env.example .env
# .env mein apna JWT_SECRET, MONGO_URI, PORT daale
node src/app.js
# Server chalu (default: http://localhost:3000)
```

---

## 🧪 Postman Testing Guide (Step-by-Step)

### 1) Register — `POST /api/auth/register`

```
POST http://localhost:3000/api/auth/register
Content-Type: application/json

Body (raw JSON):
{
  "email": "test@example.com",
  "password": "Strong@123",
  "confirmPassword": "Strong@123"
}
```

**Response:** `201 Created`

```json
{
  "success": true,
  "data": {
    "_id": "...",
    "email": "test@example.com",
    "role": "user",
    "emailVerified": false
  },
  "message": "User registered successfully..."
}
```

**Next:** Email verification token ke liye `User` model check karein (ya `console.log` mein dekhein). Usse `verify-email` call karein.

---

### 2) Verify Email — `POST /api/auth/verify-email`

```
POST http://localhost:3000/api/auth/verify-email
Content-Type: application/json

Body:
{
  "token": "<emailVerificationToken-from-db>"
}
```

**Response:** `200 OK`

```json
{ "success": true, "message": "Email verified successfully" }
```

---

### 3) Login — `POST /api/auth/login`

```
POST http://localhost:3000/api/auth/login
Content-Type: application/json

Body:
{
  "email": "test@example.com",
  "password": "Strong@123"
}
```

**Response:** `200 OK`

```json
{
  "success": true,
  "data": {
    "user": { "_id": "...", "email": "test@example.com", "role": "user" },
    "tokens": {
      "accessToken": "eyJhbG...",
      "refreshToken": "a1b2c3...",
      "accessTokenExpiry": 175...,
      "refreshTokenExpiry": 175...
    },
    "sessionId": "..."
  }
}
```

**Important:** `accessToken` ko `Authorization: Bearer <token>` mein daalein baad ke calls ke liye.

---

### 4) Authenticated Call — `GET /api/auth/profile`

```
GET http://localhost:3000/api/auth/profile
Authorization: Bearer <accessToken-from-login>
```

**Response:** `200 OK`

```json
{
  "success": true,
  "data": { "_id": "...", "email": "test@example.com", "role": "user" }
}
```

---

### 5) Refresh Token — `POST /api/auth/refresh`

```
POST http://localhost:3000/api/auth/refresh
Content-Type: application/json

Body:
{
  "refreshToken": "<refreshToken-from-login>"
}
```

**Response:** `200 OK`

```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbG...new",
    "refreshToken": "new-refresh...",
    "accessTokenExpiry": 175...,
    "refreshTokenExpiry": 175...
  }
}
```

**Note:** Yeh **rotation** karta hai — purana session revoke, naya bana.

---

### 6) Logout (Single Session) — `POST /api/auth/logout`

```
POST http://localhost:3000/api/auth/logout
Authorization: Bearer <current-accessToken>
Content-Type: application/json

Body:
{
  "sessionId": "<sessionId-from-login>"
}
```

**Response:** `200 OK`

```json
{ "success": true, "message": "Logged out successfully" }
```

---

### 7) Logout All — `POST /api/auth/logout-all`

```
POST http://localhost:3000/api/auth/logout-all
Authorization: Bearer <accessToken>
```

**Response:** `200 OK`

```json
{ "success": true, "message": "All sessions revoked successfully" }
```

---

### 8) Change Password — `PUT /api/auth/change-password`

```
PUT http://localhost:3000/api/auth/change-password
Authorization: Bearer <accessToken>
Content-Type: application/json

Body:
{
  "currentPassword": "Strong@123",
  "newPassword": "NewPass@456"
}
```

**Note:** Password change ke baad sab sessions revocate ho jate hain (security).

---

### 9) Request Password Reset — `POST /api/auth/request-password-reset`

```
POST http://localhost:3000/api/auth/request-password-reset
Content-Type: application/json

Body:
{ "email": "test@example.com" }
```

---

### 10) Reset Password — `POST /api/auth/reset-password`

```
POST http://localhost:3000/api/auth/reset-password
Content-Type: application/json

Body:
{
  "token": "<passwordResetToken-from-db>",
  "newPassword": "Reset@999",
  "confirmNewPassword": "Reset@999"
}
```

---

### 11) Admin Only — Update User Role — `PATCH /api/auth/user/:userId/role`

```
PATCH http://localhost:3000/api/auth/user/662.../role
Authorization: Bearer <admin-accessToken>
Content-Type: application/json

Body:
{ "role": "admin" }
```

**Note:** `requireAdmin` middleware laga hua hai.

---

### 12) Admin — List Users — `GET /api/users`

```
GET http://localhost:3000/api/users
Authorization: Bearer <admin-accessToken>
```

---

### 13) Admin — Get User by ID — `GET /api/users/:userId`

```
GET http://localhost:3000/api/users/662...
Authorization: Bearer <admin-accessToken>
```

---

### 14) User — Active Sessions — `GET /api/users/sessions/active`

```
GET http://localhost:3000/api/users/sessions/active
Authorization: Bearer <accessToken>
```

---

### 15) User — Delete Account — `DELETE /api/users/:userId`

```
DELETE http://localhost:3000/api/users/662...
Authorization: Bearer <accessToken>
```

---

## 🛡️ Security Headers Check (Postman)

Bina `Authorization` ke `GET /api/auth/profile` bhejein — `401` aana chahiye.

Bina `Authorization` ke `GET /api/users` bhejein — `403` aana chahiye (`requireAdmin`).

---

## ⚡ Quick Test Sequence (Recommended)

1. Register → 2. Verify Email (DB se token nikaal) → 3. Login → 4. Profile → 5. Refresh → 6. Logout → 7. Login again → 8. Change Password → 9. Logout All → 10. Admin role update

---

## 📁 Postman Collection Import

Yeh file `postman/collection.json` mein available hai — direct import kar sakte ho.

---

## ❗ Common Errors

| Error                  | Cause                      | Fix                          |
| ---------------------- | -------------------------- | ---------------------------- |
| `401 INVALID_TOKEN`    | Token expire / wrong       | Dobara login karein          |
| `423 ACCOUNT_LOCKED`   | 5 failed attempts          | 15 min wait karein           |
| `429 RATE_LIMITED`     | Too many requests          | Thoda wait karein            |
| `403 FORBIDDEN`        | Admin route h, normal user | Admin login karein           |
| `422 VALIDATION_ERROR` | Email / password format    | Validator rules check karein |

---

## 💬 Chat / Conversation Log

### Request 1 — Rate Limiting (Best Standard)
- **User ne kaha:** "ratelimiting implement for best standerd limit lagao"
- **Kya kiya:** `auth.routes.js` mein best practice rate limits update kiye

**Best Standard Rate Limit Chart (Same as applied):**

| Endpoint | Limit | Window | Key | Reason |
|---|---|---|---|---|
| **Login** | 5 | 15 min | `IP + email` | Distributed brute-force prevention |
| **Refresh** | 5 | 15 min | `IP` | Refresh rotation abuse block |
| **Register** | 3 | 15 min | `IP` | Spam account creation stop |
| **Password Reset Request** | 3 | 15 min | `IP` | Email abuse / brute stop |
| **Reset Password** | 3 | 15 min | `IP` | Token brute force stop |
| **Verify Email** | 5 | 15 min | `IP` | Verification abuse stop |

- `keyGenerator` mein `req.body.email` add kiya — distributed attacks se bachne ke liye
- `skipSuccessfulRequests: false` set kiya — har request count hoti hai (auth standard)
- `standardHeaders: true` + `legacyHeaders: false` — modern header standards

### Request 2 — Postman / API Testing Guide
- `README.md` bana — step-by-step API test instructions
- `postman/collection.json` bana — 11 requests import ke liye ready
- Variables (`accessToken`, `refreshToken`) set kiye

### Request 3 — Auth vs User Controller Difference
- `auth.controller.js`: Authentication flow (register, login, refresh, logout, verify, reset, profile, admin role/revoke)
- `user.controller.js`: User management (get all, get by id, active sessions, delete account, audit logs)
- Dono `authenticate` middleware use karte hain; auth mein `public/protected hybrid` routes hain, user mein `admin/protected` routes

---

**Author:** Production Auth System  
**Backend:** Node + Express + MongoDB + Argon2id + JWT  
**Last Updated:** Chat interaction ke baad rate limits aur docs update

---

## 🔑 Keys / Secrets

| Key                  | Purpose                   |
| -------------------- | ------------------------- |
| `JWT_ACCESS_SECRET`  | Short-lived token (15m)   |
| `JWT_REFRESH_SECRET` | Refresh token             |
| `JWT_ISSUER`         | Token issuer validation   |
| `JWT_AUDIENCE`       | Token audience validation |

---

**Author:** Production Auth System  
**Backend:** Node + Express + MongoDB + Argon2id + JWT
