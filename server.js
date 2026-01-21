require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');

// Import routes
const authRoutes = require('./routes/auth');
const kycRoutes = require('./routes/kyc');
const proofRoutes = require('./routes/proofs');
const userRoutes = require('./routes/users');

// Import middleware
const errorHandler = require('./middleware/error');

const app = express();

// Security middleware
app.use(helmet());

// CORS
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Static files for uploaded documents (temporary storage)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/kyc', kycRoutes);
app.use('/api/proofs', proofRoutes);
app.use('/api/users', userRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV 
  });
});

// Error handler
app.use(errorHandler);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Database connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      // Mongoose 8 defaults are good
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('Database connection error:', error.message);
    process.exit(1);
  }
};

// Start server
const PORT = process.env.PORT || 5000;

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════╗
║                                                   ║
║   ███████╗██╗  ██╗███████╗███████╗██╗     ███████╗║
║   ╚══███╔╝██║ ██╔╝██╔════╝██╔════╝██║     ██╔════╝║
║     ███╔╝ █████╔╝ ███████╗█████╗  ██║     █████╗  ║
║    ███╔╝  ██╔═██╗ ╚════██║██╔══╝  ██║     ██╔══╝  ║
║   ███████╗██║  ██╗███████║███████╗███████╗██║     ║
║   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝     ║
║                                                   ║
║   Privacy-First Crypto Identity                   ║
║   Server running on port ${PORT}                     ║
║   Environment: ${process.env.NODE_ENV || 'development'}                       ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
    `);
  });
});

module.exports = app;
