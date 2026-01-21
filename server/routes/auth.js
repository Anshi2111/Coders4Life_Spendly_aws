const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { sendWelcomeEmail, sendOtpEmail } = require('../services/emailService');

const router = express.Router();

// Test route to verify the router is working
router.get('/test', (req, res) => {
  res.json({ message: 'Auth routes working', timestamp: new Date().toISOString() });
});

// Test MongoDB connection
router.get('/test-db', async (req, res) => {
  console.log('📥 Test DB endpoint hit');
  
  try {
    console.log('✅ Testing MongoDB connection...');
    console.log('✅ MongoDB URI format check...');
    
    // Test basic connection first
    const mongoose = require('mongoose');
    console.log('✅ Mongoose connection state:', mongoose.connection.readyState);
    console.log('✅ Database name:', mongoose.connection.db?.databaseName);
    
    // Try a very simple operation first
    console.log('✅ Attempting simple database operation...');
    
    // Instead of User.countDocuments(), let's try a raw MongoDB operation
    const db = mongoose.connection.db;
    const collections = await db.listCollections().toArray();
    console.log('✅ Available collections:', collections.map(c => c.name));
    
    // Try to create the users collection if it doesn't exist
    if (!collections.find(c => c.name === 'users')) {
      console.log('✅ Creating users collection...');
      await db.createCollection('users');
    }
    
    // Now try to count documents
    const userCount = await User.countDocuments();
    console.log('✅ MongoDB query successful, user count:', userCount);
    
    res.json({
      success: true,
      message: 'MongoDB connection working',
      database: mongoose.connection.db?.databaseName,
      collections: collections.map(c => c.name),
      userCount: userCount
    });

  } catch (error) {
    console.error('❌ MongoDB test error:', error);
    console.error('❌ Error name:', error.name);
    console.error('❌ Error code:', error.code);
    
    res.status(500).json({ 
      success: false,
      error: 'MongoDB connection failed',
      message: error.message,
      errorName: error.name,
      errorCode: error.code
    });
  }
});

// Simple test registration (no MongoDB)
router.post('/test-register', (req, res) => {
  console.log('📥 Test register endpoint hit');
  console.log('📥 Request body:', req.body);
  
  try {
    const { email, password, name } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ 
        success: false,
        error: 'Missing required fields'
      });
    }

    // Just return success without database
    res.status(201).json({
      success: true,
      message: 'Test registration successful (no database)',
      data: { email, name }
    });

  } catch (error) {
    console.error('❌ Test registration error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Test registration failed',
      message: error.message
    });
  }
});

// Register
router.post('/register', async (req, res) => {
  console.log('📥 Register endpoint hit');
  console.log('📥 Request body:', req.body);
  console.log('📥 Headers:', req.headers);
  
  try {
    // Test 1: Basic response
    console.log('✅ Step 1: Endpoint reached');
    
    const { email, password, name, phone } = req.body;
    console.log('✅ Step 2: Destructured body');
    
    // Basic validation
    if (!email || !password || !name) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ 
        success: false,
        error: 'Missing required fields',
        message: 'Email, password, and name are required'
      });
    }

    console.log('✅ Step 3: Basic validation passed');

    // Test MongoDB connection before querying
    console.log('✅ Step 4: Testing MongoDB query...');
    
    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    console.log('✅ Step 5: MongoDB query completed, result:', !!existingUser);
    
    if (existingUser) {
      console.log('❌ User already exists');
      return res.status(409).json({ 
        success: false,
        error: 'User exists',
        message: 'User with this email already exists'
      });
    }

    console.log('✅ Step 6: User does not exist, proceeding...');

    // Hash password
    console.log('✅ Step 7: Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('✅ Step 8: Password hashed');

    // Create user
    console.log('✅ Step 9: Creating user object...');
    const newUser = new User({
      email: email.toLowerCase(),
      password: hashedPassword,
      name: name.trim(),
      phone: phone ? phone.trim() : null
    });

    console.log('✅ Step 10: Saving user to database...');
    const savedUser = await newUser.save();
    console.log('✅ Step 11: User saved to database:', savedUser._id);

    // Send welcome email (non-blocking - in background)
    console.log('✅ Step 11.5: Queuing welcome email...');
    sendWelcomeEmail(savedUser.email, savedUser.name).catch(err => {
      console.error('❌ Failed to send welcome email:', err);
    });
    console.log('✅ Step 11.6: Welcome email queued');

    // Generate token
    console.log('✅ Step 12: Generating JWT token...');
    const token = jwt.sign(
      { userId: savedUser._id, email: savedUser.email },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '7d' }
    );

    console.log('✅ Step 13: Token generated, sending response...');

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: savedUser._id,
        email: savedUser.email,
        name: savedUser.name,
        phone: savedUser.phone
      }
    });

    console.log('✅ Step 14: Response sent successfully');

  } catch (error) {
    console.error('❌ Registration error at step:', error.message);
    console.error('❌ Full error:', error);
    console.error('❌ Stack trace:', error.stack);
    
    res.status(500).json({ 
      success: false,
      error: 'Registration failed',
      message: error.message,
      step: 'Error occurred during registration process'
    });
  }
});

// Login
router.post('/login', async (req, res) => {
  console.log('📥 Login endpoint hit');
  console.log('📥 Request body:', req.body);
  
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Missing credentials',
        message: 'Email and password are required'
      });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials',
        message: 'Invalid email or password'
      });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials',
        message: 'Invalid email or password'
      });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '7d' }
    );

    console.log('✅ Login successful');

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Login failed',
      message: error.message
    });
  }
});

// Send OTP via email (Resend.com)
router.post('/send-otp', async (req, res) => {
  console.log('📥 Send OTP endpoint hit');
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        error: 'Email required'
      });
    }

    // Normalize email: trim and lowercase
    const normalizedEmail = email.trim().toLowerCase();
    console.log('📧 Normalized email:', normalizedEmail);

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid email format'
      });
    }

    // Check if user exists with this email
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      console.log('❌ User not found for email:', normalizedEmail);
      return res.status(404).json({ 
        success: false,
        error: 'Email not registered'
      });
    }

    console.log('✅ User found:', user.name);

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('📧 Generated OTP for email', normalizedEmail, ':', otp);

    // Store OTP in session/memory using normalized email (in production, use Redis)
    if (!global.otpStore) {
      global.otpStore = {};
    }
    global.otpStore[normalizedEmail] = {
      otp: otp,
      timestamp: Date.now(),
      attempts: 0
    };

    // Send OTP via Resend email (non-blocking)
    console.log('📧 Sending OTP email via Resend to:', normalizedEmail);
    sendOtpEmail(normalizedEmail, otp, user.name).catch(err => {
      console.error('❌ Failed to send OTP email via Resend:', err);
    });
    
    res.json({
      success: true,
      message: 'OTP sent successfully to your email'
    });

  } catch (error) {
    console.error('❌ Send OTP error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to send OTP',
      message: error.message
    });
  }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  console.log('📥 Verify OTP endpoint hit');
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and OTP required'
      });
    }

    // Normalize email: trim and lowercase
    const normalizedEmail = email.trim().toLowerCase();
    console.log('📧 Normalized email for verification:', normalizedEmail);

    // Check OTP
    if (!global.otpStore || !global.otpStore[normalizedEmail]) {
      console.log('❌ OTP not found for email:', normalizedEmail);
      console.log('📧 Available OTP keys:', Object.keys(global.otpStore || {}));
      return res.status(400).json({ 
        success: false,
        error: 'OTP not found or expired'
      });
    }

    const otpData = global.otpStore[normalizedEmail];
    
    // Check if OTP expired (10 minutes)
    if (Date.now() - otpData.timestamp > 10 * 60 * 1000) {
      delete global.otpStore[normalizedEmail];
      return res.status(400).json({ 
        success: false,
        error: 'OTP expired'
      });
    }

    // Check attempts
    if (otpData.attempts >= 3) {
      delete global.otpStore[normalizedEmail];
      return res.status(400).json({ 
        success: false,
        error: 'Too many attempts. Request a new OTP'
      });
    }

    // Verify OTP
    if (otpData.otp !== otp) {
      otpData.attempts++;
      return res.status(400).json({ 
        success: false,
        error: 'Invalid OTP'
      });
    }

    // OTP verified - mark as verified
    otpData.verified = true;
    console.log('✅ OTP verified for email:', normalizedEmail);

    res.json({
      success: true,
      message: 'OTP verified successfully'
    });

  } catch (error) {
    console.error('❌ Verify OTP error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to verify OTP',
      message: error.message
    });
  }
});

// Reset password
router.post('/reset-password', async (req, res) => {
  console.log('📥 Reset password endpoint hit');
  try {
    const { email, newPassword } = req.body;
    
    if (!email || !newPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and new password required'
      });
    }

    // Normalize email: trim and lowercase
    const normalizedEmail = email.trim().toLowerCase();
    console.log('📧 Normalized email for password reset:', normalizedEmail);

    // Check if OTP was verified
    if (!global.otpStore || !global.otpStore[normalizedEmail] || !global.otpStore[normalizedEmail].verified) {
      console.log('❌ OTP not verified for email:', normalizedEmail);
      return res.status(400).json({ 
        success: false,
        error: 'OTP verification required'
      });
    }

    // Find user
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      console.log('❌ User not found for email:', normalizedEmail);
      return res.status(404).json({ 
        success: false,
        error: 'User not found'
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password
    user.password = hashedPassword;
    await user.save();

    // Clear OTP
    delete global.otpStore[normalizedEmail];

    console.log('✅ Password reset for email:', normalizedEmail);

    res.json({
      success: true,
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to reset password',
      message: error.message
    });
  }
});

module.exports = router;