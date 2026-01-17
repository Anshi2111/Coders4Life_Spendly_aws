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