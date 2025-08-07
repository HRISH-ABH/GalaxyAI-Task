
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();
import connectDb from './db/db.js';
connectDb();
import authRoutes from "./routes/auth.route.js";
import chatRoutes from "./routes/chat.route.js";
import uploadRoutes from "./routes/upload.route.js";


const app = express();


app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use('/api/auth', authRoutes);
app.use('/api/chat', chatRoutes);
app.use('/api/upload', uploadRoutes);

export default app;

