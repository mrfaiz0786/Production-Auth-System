import { validationResult } from 'express-validator';
import { AppError } from './errorHandler.js';

export const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map((validation) => validation.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map((err) => ({
        field: err.path,
        message: err.msg,
        location: err.location,
      }));
      throw new AppError('Validation failed', 422, 'VALIDATION_ERROR', errorMessages);
    }
    next();
  };
};