import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const app = express();

// BASIC CONFIGURATION
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));
app.use(express.static('public'));

// FOR COOKIES

app.use(cookieParser());

// CORS CONFIGURATION
app.use(
  cors({
    origin: process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',')
      : ['http://localhost:5173'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }),
);

// IMPORT THE ROUTES

import healthCheckRouter from './routes/healthCheck.routes.js';
import authRouter from './routes/auth.routes.js';

app.use('/api/v1/healthCheck', healthCheckRouter);
app.use('/api/v1/auth', authRouter);

app.get('/', (req, res) => {
  res.send('Hello World!');
});

export default app;
