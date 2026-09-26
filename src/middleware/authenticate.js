import { config } from '../config.js';
import { verifyAccessToken, decodeToken } from '../utils/token.js';
import { Session } from '../models/Session.js';
import { User } from '../models/User.js';
import { AppError } from './errorHandler.js';

export const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError('No token provided', 401, 'UNAUTHORIZED');
    }

    const token = authHeader.split(' ')[1];
    
    let decoded;
    try {
      decoded = verifyAccessToken(token);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        throw new AppError('Token expired', 401, 'TOKEN_EXPIRED');
      }
      throw new AppError('Invalid token', 401, 'INVALID_TOKEN');
    }

    // Check if session exists and is not revoked
    const session = await Session.findOne({
      userId: decoded.sub,
      revoked: false,
      expiresAt: { $gt: new Date() },
    });

    if (!session) {
      throw new AppError('Session revoked or expired', 401, 'SESSION_REVOKED');
    }

    // Check if token was issued before session creation (for rotation)
    const tokenIat = decoded.iat * 1000;
    const sessionCreated = session.createdAt.getTime();
    if (tokenIat < sessionCreated) {
      throw new AppError('Token revoked due to refresh', 401, 'TOKEN_REVOKED');
    }

    // Get user with current permissions
    const user = await User.findById(decoded.sub).select('-passwordHash');
    if (!user) {
      throw new AppError('User not found', 401, 'USER_NOT_FOUND');
    }

    if (user.refreshTokenVersion !== decoded.tokenVersion) {
      throw new AppError('Token revoked', 401, 'TOKEN_REVOKED');
    }

    req.user = user;
    req.sessionId = session._id;
    req.token = token;
    next();
  } catch (err) {
    next(err);
  }
};

export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      return next();
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyAccessToken(token);
    
    const user = await User.findById(decoded.sub).select('-passwordHash');
    if (user) {
      req.user = user;
    }
  } catch (err) {
    // Ignore errors for optional auth
  }
  next();
};