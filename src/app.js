import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import https from 'https';
import fs from 'fs';
import { config } from './config.js';
import { authRoutes } from './routes/auth.routes.js';
import { userRoutes } from './routes/user.routes.js';
import { errorHandler, notFound } from './middleware/errorHandler.js';
import { AppError } from './middleware/errorHandler.js';

const app = express();

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: config.nodeEnv === 'production' ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// CORS properly configured
app.use(cors({
  origin: config.corsOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-Token-Expired'],
  maxAge: 86400,
}));

// Parse cookies (for refresh token cookie if needed)
app.use(cookieParser());

// Body parser
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// Trust proxy settings
app.set('trust proxy', 1);

// Security middleware
app.use((req, res, next) => {
  // Force HTTPS in production
  if (config.httpsEnabled && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Database connection
mongoose.connect(config.mongoUri, {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
  maxPoolSize: 10,
}).then(() => {
  console.log('Database connected');
}).catch(err => {
  console.error('Database connection error:', err);
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB error:', err);
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'UP', time: new Date().toISOString() });
});

// Not found handler
app.use(notFound);

// Global error handler
app.use(errorHandler);

// HTTPS server setup
if (config.httpsEnabled && config.httpsCertPath && config.httpsKeyPath) {
  const httpsOptions = {
    key: fs.readFileSync(config.httpsKeyPath),
    cert: fs.readFileSync(config.httpsCertPath),
  };
  const server = https.createServer(httpsOptions, app);
  server.listen(config.port, () => {
    console.log(`HTTPS server running on port ${config.port}`);
  });
} else {
  app.listen(config.port, () => {
    console.log(`HTTP server running on port ${config.port}`);
  });
}

export { app };