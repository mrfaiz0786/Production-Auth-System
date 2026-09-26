import express from 'express';
import { register, login, refresh, logout, logoutAll, verifyEmail, requestPasswordReset, resetPassword, changePassword, getProfile, updateRole, revokeUserSessions } from '../controllers/auth.controller.js';
import { authenticate } from '../middleware/authenticate.js';
import { requireAdmin, requireRole } from '../middleware/authorize.js';
import { validate } from '../middleware/validate.js';
import { registerValidator, loginValidator, refreshValidator, emailVerificationValidator, passwordResetValidator, emailValidator, idValidator } from '../validators/auth.validator.js';
import rateLimit from 'express-rate-limit';
import { body } from 'express-validator';

const router = express.Router();

// Best practice rate limits for production auth
// Login: 5 attempts / 15 min (IP + email based)
// Refresh: 5 attempts / 15 min (IP based)
// Register: 3 attempts / 15 min (IP based) — prevents spam accounts
// Password reset: 3 attempts / 15 min (IP based) — prevents brute force
// Verify email: 5 attempts / 15 min (IP based)
const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many login attempts. Try again after 15 minutes.' } },
  standardHeaders: true,
  legacyHeaders: false,
  // Best practice: key by both IP and email to prevent distributed brute force
  keyGenerator: (req) => req.ip || req.connection.remoteAddress + ':' + (req.body?.email || 'unknown'),
  skipSuccessfulRequests: false, // Count all attempts for auth
});

const refreshRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Stricter: refresh is sensitive — rotation abuse prevention
  message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many refresh attempts. Try again after 15 minutes.' } },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || req.connection.remoteAddress,
});

const registerRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many registrations from this IP. Try again after 15 minutes.' } },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || req.connection.remoteAddress,
});

const passwordResetRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many reset requests. Try again after 15 minutes.' } },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || req.connection.remoteAddress,
});

const verifyEmailRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many verification attempts. Try again after 15 minutes.' } },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || req.connection.remoteAddress,
});

// Public routes
router.post('/register', registerRateLimit, validate(registerValidator), register);
router.post('/login', loginRateLimit, validate(loginValidator), login);
router.post('/refresh', refreshRateLimit, validate(refreshValidator), refresh);
router.post('/verify-email', verifyEmailRateLimit, validate(emailVerificationValidator), verifyEmail);
router.post('/request-password-reset', passwordResetRateLimit, validate(emailValidator), requestPasswordReset);
router.post('/reset-password', passwordResetRateLimit, validate(passwordResetValidator), resetPassword);

// Protected routes
router.post('/logout', authenticate, logout);
router.post('/logout-all', authenticate, logoutAll);
router.put('/change-password', authenticate, validate([
  body('currentPassword').isLength({ min: 1 }),
  body('newPassword').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/),
]), changePassword);
router.get('/profile', authenticate, getProfile);

// Admin routes
router.patch('/user/:userId/role', authenticate, requireAdmin, validate(idValidator), validate([
  body('role').isIn(['user', 'admin', 'moderator']).withMessage('Invalid role')
]), updateRole);
router.post('/user/:userId/revoke-sessions', authenticate, requireAdmin, validate(idValidator), revokeUserSessions);

export const authRoutes = router;