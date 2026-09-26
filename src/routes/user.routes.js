import express from 'express';
import { getAllUsers, getUserById, getActiveSessions, deleteAccount, getAuditLogs } from '../controllers/user.controller.js';
import { authenticate } from '../middleware/authenticate.js';
import { requireAdmin } from '../middleware/authorize.js';
import { idValidator, userIdValidator } from '../validators/auth.validator.js';
import { validate } from '../middleware/validate.js';

const router = express.Router();

router.get('/', authenticate, requireAdmin, getAllUsers);
router.get('/:userId', authenticate, validate(idValidator), getUserById);
router.get('/sessions/active', authenticate, getActiveSessions);
router.delete('/:userId', authenticate, validate(idValidator), deleteAccount);
router.get('/audit/logs', authenticate, requireAdmin, getAuditLogs);

export const userRoutes = router;