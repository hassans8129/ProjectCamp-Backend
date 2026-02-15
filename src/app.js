import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { ApiError } from './utils/Api_error.js';

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

// Error handling middleware (this catches all errors passed to next())
app.use((err, req, res, next) => {
  // If it's your custom ApiError
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      success: err.success,
      message: err.message,
      errors: err.errors,
    });
  }

  // For mongoose errors or other unexpected errors
  return res.status(500).json({
    success: false,
    message: err.message || 'Internal Server Error',
    errors: [],
  });
});

export default app;
