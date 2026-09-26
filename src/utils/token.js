import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';

const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';
const EMAIL_VERIFICATION_EXPIRY = '24h';
const PASSWORD_RESET_EXPIRY = '1h';

export const generateAccessToken = (user, sessionId = null) => {
  // Defensive: handle both Mongoose docs and plain objects
  const userId = user && user._id ? user._id.toString() : (user ? user.sub : 'unknown');
  const userEmail = user ? user.email : '';
  return jwt.sign(
    {
      sub: userId,
      email: userEmail,
      role: user ? user.role : '',
      permissions: (user && user.permissions) ? user.permissions : [],
      sessionId: sessionId ? sessionId.toString() : (user && user.activeSessionId ? user.activeSessionId.toString() : null),
    },
    config.jwtAccessSecret,
    {
      expiresIn: ACCESS_TOKEN_EXPIRY,
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      jwtid: crypto.randomUUID(),
    }
  );
};

export const generateRefreshToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

export const hashRefreshToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

export const generateEmailVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

export const generatePasswordResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

export const verifyAccessToken = (token) => {
  return jwt.verify(token, config.jwtAccessSecret, {
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
    algorithms: ['HS256'],
  });
};

export const verifyRefreshToken = (token) => {
  return jwt.verify(token, config.jwtRefreshSecret, {
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
    algorithms: ['HS256'],
  });
};

export const decodeToken = (token) => {
  return jwt.decode(token);
};

export const createTokenPair = async (user, sessionId) => {
  const accessToken = generateAccessToken(user, sessionId);
  const refreshToken = generateRefreshToken();
  const refreshTokenHash = hashRefreshToken(refreshToken);

  return {
    accessToken,
    refreshToken,
    refreshTokenHash,
    accessTokenExpiry: Date.now() + 15 * 60 * 1000,
    refreshTokenExpiry: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
};

export const getTokenExpiry = (token) => {
  const decoded = decodeToken(token);
  return decoded?.exp ? decoded.exp * 1000 : null;
};