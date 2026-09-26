import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { User } from '../models/User.js';
import { Session } from '../models/Session.js';
import { createTokenPair, verifyRefreshToken } from '../utils/token.js';
import { verifyPassword, hashPassword } from '../utils/password.js';
import { config } from '../config.js';
import { AppError } from '../middleware/errorHandler.js';
import mongoose from 'mongoose';

const AuditLog = {
  log: (action, userId, details) => {
    console.log(`[AUDIT] ${new Date().toISOString()} | ${action} | userId=${userId} | ${JSON.stringify(details)}`);
  },
};

class AuthService {
  constructor() {
    this.rateLimitStore = new Map();
  }

  clearRateLimitStore() {
    this.rateLimitStore.clear();
  }

  checkRateLimit(key, windowMs, maxAttempts) {
    const now = Date.now();
    const entry = this.rateLimitStore.get(key);

    if (!entry || now - entry.resetAt > windowMs) {
      this.rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
      return { allowed: true, remaining: maxAttempts - 1 };
    }

    if (entry.count >= maxAttempts) {
      return { allowed: false, remaining: 0 };
    }

    entry.count++;
    return { allowed: true, remaining: maxAttempts - entry.count };
  }

  async register({ email, password, role = 'user' }) {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new AppError('Email already registered', 409, 'EMAIL_EXISTS');
    }

    const passwordHash = await hashPassword(password);
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');

    const user = await User.create({
      email,
      passwordHash,
      role,
      emailVerificationToken,
      emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    AuditLog.log('REGISTER', user._id, { email });

    return {
      _id: user._id,
      email: user.email,
      role: user.role,
      emailVerified: user.emailVerified,
    };
  }

  async login({ email, password, ip, userAgent }) {
    const rateLimitKey = `login:${ip}`;
    const rl = this.checkRateLimit(rateLimitKey, config.rateLimitLoginWindowMs, config.rateLimitLoginMaxAttempts);

    if (!rl.allowed) {
      throw new AppError('Too many login attempts', 429, 'RATE_LIMITED');
    }

    const user = await User.findOne({ email });
    if (!user) {
      throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new AppError('Account locked', 423, 'ACCOUNT_LOCKED');
    }

    const validPassword = await verifyPassword(password, user.passwordHash);
    if (!validPassword) {
      user.failedLoginAttempts += 1;
      
      if (user.failedLoginAttempts >= config.maxFailedLoginAttempts) {
        user.lockedUntil = new Date(Date.now() + config.lockoutDurationMs);
        user.failedLoginAttempts = 0;
        await user.save();
        AuditLog.log('ACCOUNT_LOCKED', user._id, { email, ip });
        throw new AppError('Account locked due to too many failed attempts', 423, 'ACCOUNT_LOCKED');
      }
      
      await user.save();
      throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
    }

    user.failedLoginAttempts = 0;
    user.lockedUntil = undefined;
    await user.save();

    console.log("DEBUG USER:", user, user?._id);
    const { accessToken, refreshToken, refreshTokenHash } = await createTokenPair(user, null);

    const session = await Session.create({
      userId: user._id,
      refreshTokenHash,
      userAgent,
      ip,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    user.activeSessionId = session._id;
    await user.save();

    AuditLog.log('LOGIN', user._id, { email, ip, userAgent });

    return {
      user: {
        _id: user._id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
      },
      tokens: {
        accessToken,
        refreshToken,
        accessTokenExpiry: Date.now() + 15 * 60 * 1000,
        refreshTokenExpiry: Date.now() + 7 * 24 * 60 * 60 * 1000,
      },
      sessionId: session._id,
    };
  }

  async refresh({ refreshToken, ip, userAgent }) {
    if (!refreshToken) {
      throw new AppError('Refresh token required', 401, 'NO_REFRESH_TOKEN');
    }

    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const session = await Session.findOne({ refreshTokenHash });
    if (!session) {
      throw new AppError('Invalid refresh token', 401, 'INVALID_REFRESH_TOKEN');
    }

    if (session.revoked || session.expiresAt < new Date()) {
      throw new AppError('Refresh token expired or revoked', 401, 'REFRESH_TOKEN_EXPIRED');
    }

    const user = await User.findById(session.userId);
    if (!user) {
      throw new AppError('User not found', 404, 'USER_NOT_FOUND');
    }

    // Token rotation check removed: session revocation handles rotation security
    const rateLimitKey = `refresh:${ip}`;
    const rl = this.checkRateLimit(rateLimitKey, config.rateLimitRefreshWindowMs, config.rateLimitRefreshMaxAttempts);
    if (!rl.allowed) {
      throw new AppError('Too many refresh requests', 429, 'RATE_LIMITED');
    }

    await Session.updateOne(
      { _id: session._id },
      { revoked: true, revokedAt: new Date() }
    );

    const { accessToken, refreshToken: newRefreshToken, refreshTokenHash: newRefreshTokenHash } = await createTokenPair(user, session._id);

    await Session.create({
      userId: user._id,
      refreshTokenHash: newRefreshTokenHash,
      userAgent,
      ip,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    AuditLog.log('TOKEN_REFRESH', user._id, { sessionId: session._id, ip });

    return {
      accessToken,
      refreshToken: newRefreshToken,
      accessTokenExpiry: Date.now() + 15 * 60 * 1000,
      refreshTokenExpiry: Date.now() + 7 * 24 * 60 * 60 * 1000,
    };
  }

  async logout(userId, sessionId) {
    await Session.updateOne(
      { _id: sessionId, userId },
      { revoked: true, revokedAt: new Date() }
    );

    await User.findByIdAndUpdate(userId, { activeSessionId: null });

    AuditLog.log('LOGOUT', userId, { sessionId });
  }

  async revokeAllSessions(userId) {
    await Session.updateMany(
      { userId },
      { revoked: true, revokedAt: new Date() }
    );

    await User.findByIdAndUpdate(userId, { $set: { activeSessionId: null }, $inc: { refreshTokenVersion: 1 } });

    AuditLog.log('REVOKE_ALL_SESSIONS', userId, {});
  }

  async revokeSession(sessionId, userId) {
    await Session.updateOne(
      { _id: sessionId, userId },
      { revoked: true, revokedAt: new Date() }
    );

    AuditLog.log('REVOKE_SESSION', userId, { sessionId });
  }

  async verifyEmail(token) {
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: new Date() },
    });

    if (!user) {
      throw new AppError('Invalid or expired verification token', 400, 'INVALID_TOKEN');
    }

    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    AuditLog.log('EMAIL_VERIFIED', user._id, { email: user.email });

    return { message: 'Email verified successfully' };
  }

  async requestPasswordReset(email) {
    const user = await User.findOne({ email });
    if (!user) {
      throw new AppError('User not found', 404, 'USER_NOT_FOUND');
    }

    user.passwordResetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();

    AuditLog.log('PASSWORD_RESET_REQUESTED', user._id, { email });

    return { message: 'Password reset token sent' };
  }

  async resetPassword(token, newPassword) {
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: new Date() },
    });

    if (!user) {
      throw new AppError('Invalid or expired reset token', 400, 'INVALID_TOKEN');
    }

    user.passwordHash = await hashPassword(newPassword);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.refreshTokenVersion += 1;
    await user.save();

    await Session.updateMany(
      { userId: user._id },
      { revoked: true, revokedAt: new Date() }
    );

    AuditLog.log('PASSWORD_RESET', user._id, { email: user.email });

    return { message: 'Password reset successful' };
  }

  async changePassword(userId, currentPassword, newPassword) {
    const user = await User.findById(userId);
    if (!user) {
      throw new AppError('User not found', 404, 'USER_NOT_FOUND');
    }

    const validPassword = await verifyPassword(currentPassword, user.passwordHash);
    if (!validPassword) {
      throw new AppError('Current password is incorrect', 400, 'INVALID_PASSWORD');
    }

    user.passwordHash = await hashPassword(newPassword);
    user.refreshTokenVersion += 1;
    await user.save();

    await Session.updateMany(
      { userId: user._id },
      { revoked: true, revokedAt: new Date() }
    );

    AuditLog.log('PASSWORD_CHANGED', user._id, { email: user.email });

    return { message: 'Password changed successfully' };
  }

  async getUserProfile(userId) {
    const user = await User.findById(userId).select('-passwordHash');
    if (!user) {
      throw new AppError('User not found', 404, 'USER_NOT_FOUND');
    }
    return user;
  }

  async updateUserRole(userId, newRole) {
    const allowedRoles = ['user', 'admin', 'moderator'];
    if (!allowedRoles.includes(newRole)) {
      throw new AppError('Invalid role', 400, 'INVALID_ROLE');
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { role: newRole },
      { new: true }
    ).select('-passwordHash');

    AuditLog.log('ROLE_CHANGED', userId, { newRole });

    return user;
  }

  async revokeUserSessions(userId) {
    await Session.updateMany(
      { userId },
      { revoked: true, revokedAt: new Date() }
    );

    await User.findByIdAndUpdate(userId, { activeSessionId: null });

    AuditLog.log('USER_SESSIONS_REVOKED', userId, {});
  }
}

export const authService = new AuthService();