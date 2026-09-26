import dotenv from 'dotenv';

dotenv.config();

export const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,

  // Database
  mongoUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_db',

  // JWT
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET || 'change-me-access-secret-min-32-chars!',
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'change-me-refresh-secret-min-32-chars!',
  jwtIssuer: process.env.JWT_ISSUER || 'https://auth.yourdomain.com',
  jwtAudience: process.env.JWT_AUDIENCE || 'https://api.yourdomain.com',

  // Cookie
  cookieDomain: process.env.COOKIE_DOMAIN || 'localhost',
  cookieSecure: process.env.NODE_ENV === 'production',
  cookieSameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',

  // Rate Limiting
  rateLimitLoginWindowMs: 15 * 60 * 1000,
  rateLimitLoginMaxAttempts: 5,
  rateLimitRefreshWindowMs: 15 * 60 * 1000,
  rateLimitRefreshMaxAttempts: 10,

  // Account Lockout
  maxFailedLoginAttempts: 5,
  lockoutDurationMs: 15 * 60 * 1000,

  // HTTPS
  httpsEnabled: process.env.HTTPS_ENABLED === 'true',
  httpsCertPath: process.env.HTTPS_CERT_PATH,
  httpsKeyPath: process.env.HTTPS_KEY_PATH,

  // CORS
  corsOrigin: process.env.CORS_ORIGIN || 'https://yourdomain.com',

  // Audit
  auditLogEnabled: process.env.AUDIT_LOG_ENABLED === 'true',
};