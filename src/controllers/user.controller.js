import { User } from '../models/User.js';
import { Session } from '../models/Session.js';
import { AppError } from '../middleware/errorHandler.js';
import { authService } from '../services/auth.service.js';

export const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find({}).select('-passwordHash -emailVerificationToken -passwordResetToken');

    res.status(200).json({
      success: true,
      data: users,
    });
  } catch (err) {
    next(err);
  }
};

export const getUserById = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId).select('-passwordHash');
    if (!user) {
      throw new AppError('User not found', 404, 'NOT_FOUND');
    }

    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (err) {
    next(err);
  }
};

export const getActiveSessions = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const sessions = await Session.find({ userId, revoked: false }).select('userAgent ip createdAt');

    res.status(200).json({
      success: true,
      data: sessions,
    });
  } catch (err) {
    next(err);
  }
};

export const deleteAccount = async (req, res, next) => {
  try {
    const userId = req.params.userId || req.user._id;
    
    if (req.user.role !== 'admin' && req.user._id.toString() !== userId) {
      throw new AppError('Not authorized to delete this account', 403, 'FORBIDDEN');
    }

    await User.findByIdAndDelete(userId);
    await Session.deleteMany({ userId });

    res.status(200).json({
      success: true,
      message: 'Account deleted successfully',
    });
  } catch (err) {
    next(err);
  }
};

export const getAuditLogs = async (req, res, next) => {
  try {
    // In a real application, you'd query an audit log database
    res.status(200).json({
      success: true,
      message: 'Audit logs retrieved',
      data: [],
    });
  } catch (err) {
    next(err);
  }
};