const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

// Test route to verify the router is working
router.get('/test', (req, res) => {
  res.json({ message: 'Auth routes working', timestamp: new Date().toISOString() });
});

// Register
router.post('/register', async (req, res) => {
  console.log('📥 Register endpoint hit');
  console.log('📥 Request body:', req.body);
  
  try {
    const { email, password, name, phone } = req.body;
    
    // Basic validation
    if (!email || !password || !name) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ 
        success: false,
        error: 'Missing required fields',
        message: 'Email, password, and name are required'
      });
    }

    console.log('✅ Basic validation passed');

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      console.log('❌ User already exists');
      return res.status(409).json({ 
        success: false,
        error: 'User exists',
        message: 'User with this email already exists'
      });
    }

    console.log('✅ User does not exist, creating new user');

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('✅ Password hashed');

    // Create user
    const newUser = new User({
      email: email.toLowerCase(),
      password: hashedPassword,
      name: name.trim(),
      phone: phone ? phone.trim() : null
    });

    const savedUser = await newUser.save();
    console.log('✅ User saved to database:', savedUser._id);

    // Generate token
    const token = jwt.sign(
      { userId: savedUser._id, email: savedUser.email },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '7d' }
    );

    console.log('✅ Token generated');

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

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Registration failed',
      message: error.message
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

// Simple OTP routes (minimal for now)
router.post('/send-otp', async (req, res) => {
  console.log('📥 Send OTP endpoint hit');
  try {
    const { phone } = req.body;
    
    if (!phone) {
      return res.status(400).json({ 
        success: false,
        error: 'Phone number required'
      });
    }

    // For now, just return success (implement SMS later)
    console.log('📱 OTP would be sent to:', phone);
    
    res.json({
      success: true,
      message: 'OTP sent successfully (development mode)'
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

router.post('/verify-otp', (req, res) => {
  console.log('📥 Verify OTP endpoint hit');
  res.json({
    success: true,
    message: 'OTP verified (development mode)'
  });
});

router.post('/reset-password', (req, res) => {
  console.log('📥 Reset password endpoint hit');
  res.json({
    success: true,
    message: 'Password reset (development mode)'
  });
});

module.exports = router;