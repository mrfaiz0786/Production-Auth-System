import { body, param } from 'express-validator';

export const registerValidator = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email address'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*&]/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match');
      }
      return true;
    }),
];

export const loginValidator = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email address'),
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password is required'),
];

export const refreshValidator = [
  body('refreshToken')
    .isString()
    .withMessage('Refresh token is required'),
];

export const emailVerificationValidator = [
  body('token')
    .isString()
    .withMessage('Token is required'),
];

export const passwordResetValidator = [
  body('token')
    .isString()
    .withMessage('Token is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*&]/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character'),
  body('confirmNewPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match');
      }
      return true;
    }),
];

export const emailValidator = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email address'),
];

export const idValidator = [
  param('id')
    .isMongoId()
    .withMessage('Invalid ID'),
];

export const userIdValidator = [
  param('userId')
    .isMongoId()
    .withMessage('Invalid user ID'),
];

export const permissionValidator = [
  body('permission')
    .isString()
    .withMessage('Permission is required')
    .trim(),
];