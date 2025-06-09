import { Router } from 'express';
import authRoutes from './auth-routes.js';
import apiRoutes from './api/index.js';
import { authenticateToken } from '../middleware/auth.js';

const router = Router();

router.use('/api/auth', authRoutes); // Authentication routes

// TODO: Add authentication to the API routes
router.use('/api', authenticateToken, apiRoutes); // Secure all /api routes with JWT

export default router;
