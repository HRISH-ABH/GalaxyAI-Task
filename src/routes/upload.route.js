import express from 'express';
import authMiddleware from '../middlewares/auth.middleware.js';
import { uploadMiddleware } from '../middlewares/upload.middleware.js';
import { uploadFileController } from '../controllers/upload.controller.js';

const router = express.Router();

router.post('/', authMiddleware, uploadMiddleware, uploadFileController);

export default router;
