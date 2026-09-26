import { AppError } from './errorHandler.js';

export const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError('Authentication required', 403, 'FORBIDDEN');
      }

      if (!allowedRoles.includes(req.user.role)) {
        throw new AppError('Insufficient privileges', 403, 'FORBIDDEN');
      }

      next();
    } catch (err) {
      next(err);
    }
  };
};

export const requirePermission = (permission) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError('Authentication required', 403, 'FORBIDDEN');
      }

      const permissions = req.user.permissions || [];
      if (!permissions.includes(permission) && req.user.role === 'user') {
        throw new AppError('Missing permission: ' + permission, 403, 'INSUFFICIENT_PERMISSIONS');
      }

      next();
    } catch (err) {
      next(err);
    }
  };
};

export const requireOwnership = (modelName) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError('Authentication required', 403, 'FORBIDDEN');
      }

      const Model = require(`../models/${modelName}.js`);
      const resource = await Model.findById(req.params.id || req.params.userId || req.params.resourceId);
      
      if (!resource) {
        throw new AppError('Resource not found', 404, 'NOT_FOUND');
      }

      const ownerId = resource.userId?.toString() || resource.user?.toString() || resource.owner?.toString();
      
      // Admin can access anything
      if (req.user.role === 'admin') {
        req.resource = resource;
        return next();
      }

      // Controller must check if user owns it or has permission
      if (ownerId && ownerId !== req.user._id.toString()) {
        // Check permissions
        const hasAccess = req.user.permissions?.some(p => p === `${modelName}:read:all` || p === `${modelName}:manage:all`);
        if (!hasAccess) {
          throw new AppError('Not authorized to access this resource', 403, 'NOT_OWNER');
        }
      }

      req.resource = resource;
      next();
    } catch (err) {
      next(err);
    }
  };
};

export const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return next(new AppError('Authentication required', 403, 'FORBIDDEN'));
  }
  if (req.user.role !== 'admin') {
    return next(new AppError('Admin access required', 403, 'FORBIDDEN'));
  }
  next();
};