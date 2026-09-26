import { authService } from '../services/auth.service.js';
import { AppError } from '../middleware/errorHandler.js';
import { config } from '../config.js';

export const register = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';

    const result = await authService.register({ email, password, role: 'user' });

    res.status(201).json({
      success: true,
      data: result,
      message: 'User registered successfully. Please check your email to verify your account.',
    });
  } catch (err) {
    next(err);
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';

    const result = await authService.login({ email, password, ip, userAgent });

    res.status(200).json({
      success: true,
      data: result,
      message: 'Login successful',
    });
  } catch (err) {
    next(err);
  }
};

export const refresh = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';

    const result = await authService.refresh({ refreshToken, ip, userAgent });

    res.status(200).json({
      success: true,
      data: result,
      message: 'Token refreshed successfully',
    });
  } catch (err) {
    next(err);
  }
};

export const logout = async (req, res, next) => {
  try {
    const { sessionId } = req.body;
    const userId = req.user._id;

    await authService.logout(userId, sessionId);

    res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (err) {
    next(err);
  }
};

export const logoutAll = async (req, res, next) => {
  try {
    const userId = req.user._id;
    await authService.revokeAllSessions(userId);

    res.status(200).json({
      success: true,
      message: 'All sessions revoked successfully',
    });
  } catch (err) {
    next(err);
  }
};

export const verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.body;

    const result = await authService.verifyEmail(token);

    res.status(200).json({
      success: true,
      message: result.message,
    });
  } catch (err) {
    next(err);
  }
};

export const requestPasswordReset = async (req, res, next) => {
  try {
    const { email } = req.body;

    const result = await authService.requestPasswordReset(email);

    res.status(200).json({
      success: true,
      message: result.message,
    });
  } catch (err) {
    next(err);
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;

    const result = await authService.resetPassword(token, newPassword);

    res.status(200).json({
      success: true,
      message: result.message,
    });
  } catch (err) {
    next(err);
  }
};

export const changePassword = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const { currentPassword, newPassword } = req.body;

    const result = await authService.changePassword(userId, currentPassword, newPassword);

    res.status(200).json({
      success: true,
      message: result.message,
    });
  } catch (err) {
    next(err);
  }
};

export const getProfile = async (req, res, next) => {
  try {
    const user = await authService.getUserProfile(req.user._id);

    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (err) {
    next(err);
  }
};

export const updateRole = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    const user = await authService.updateUserRole(userId, role);

    res.status(200).json({
      success: true,
      data: user,
      message: 'User role updated successfully',
    });
  } catch (err) {
    next(err);
  }
};

export const revokeUserSessions = async (req, res, next) => {
  try {
    const { userId } = req.params;
    await authService.revokeUserSessions(userId);

    res.status(200).json({
      success: true,
      message: 'All user sessions revoked successfully',
    });
  } catch (err) {
    next(err);
  }
};