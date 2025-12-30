const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getDatabase } = require('../database/init');

const router = express.Router();

// In-memory OTP storage (in production, use Redis or database)
const otpStore = new Map();

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP (Mock implementation - replace with real SMS service)
const sendSMS = async (phone, otp) => {
  // In production, integrate with SMS service like Twilio, AWS SNS, etc.
  console.log(`📱 SMS to ${phone}: Your Spendly OTP is ${otp}. Valid for 5 minutes.`);
  
  // Simulate SMS sending delay
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  return { success: true };
};

// Register
router.post('/register', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        message: 'Email and password are required'
      });
    }

    if (!phone) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        message: 'Phone number is required'
      });
    }

    // Validate phone number format (Indian mobile)
    const phoneRegex = /^[6-9]\d{9}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ 
        error: 'Invalid phone number',
        message: 'Phone number must be a valid 10-digit Indian mobile number'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        error: 'Invalid password',
        message: 'Password must be at least 6 characters long'
      });
    }

    const db = getDatabase();
    
    // Check if user exists with email or phone
    db.get('SELECT id FROM users WHERE email = ? OR phone = ?', [email, phone], async (err, row) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ 
          error: 'Database error',
          message: 'Failed to check user existence'
        });
      }
      
      if (row) {
        return res.status(409).json({ 
          error: 'User exists',
          message: 'User with this email or phone number already exists'
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Create user
      db.run(
        'INSERT INTO users (email, password, name, phone) VALUES (?, ?, ?, ?)',
        [email, hashedPassword, name || '', phone],
        function(err) {
          if (err) {
            console.error('❌ Failed to create user:', err);
            return res.status(500).json({ 
              error: 'Registration failed',
              message: 'Failed to create user account'
            });
          }
          
          const token = jwt.sign(
            { userId: this.lastID, email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
          );
          
          console.log('✅ User registered:', email, phone);
          res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
              id: this.lastID,
              email,
              name: name || '',
              phone
            }
          });
        }
      );
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      error: 'Server error',
      message: 'Internal server error during registration'
    });
  }
});

// Login
router.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Missing credentials',
        message: 'Email and password are required'
      });
    }

    const db = getDatabase();
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ 
          error: 'Database error',
          message: 'Failed to authenticate user'
        });
      }
      
      if (!user) {
        return res.status(401).json({ 
          error: 'Invalid credentials',
          message: 'Email or password is incorrect'
        });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ 
          error: 'Invalid credentials',
          message: 'Email or password is incorrect'
        });
      }

      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );
      
      console.log('✅ User logged in:', email);
      res.json({
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          phone: user.phone,
          salary: user.salary
        }
      });
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      error: 'Server error',
      message: 'Internal server error during login'
    });
  }
});

// Send OTP for password reset
router.post('/send-otp', async (req, res) => {
  try {
    const { phone } = req.body;
    
    if (!phone) {
      return res.status(400).json({ 
        success: false,
        error: 'Phone number is required'
      });
    }

    // Validate phone number format (Indian mobile)
    const phoneRegex = /^[6-9]\d{9}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid phone number format'
      });
    }

    const db = getDatabase();
    
    // Check if user exists with this phone number
    db.get('SELECT id, email FROM users WHERE phone = ?', [phone], async (err, user) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ 
          success: false,
          error: 'Database error'
        });
      }
      
      if (!user) {
        return res.status(404).json({ 
          success: false,
          error: 'Phone number not registered'
        });
      }

      // Generate OTP
      const otp = generateOTP();
      const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
      
      // Store OTP
      otpStore.set(phone, {
        otp,
        expiresAt,
        attempts: 0,
        verified: false
      });

      try {
        // Send SMS
        await sendSMS(phone, otp);
        
        console.log(`✅ OTP sent to ${phone}`);
        res.json({
          success: true,
          message: 'OTP sent successfully'
        });
      } catch (smsError) {
        console.error('❌ SMS sending failed:', smsError);
        res.status(500).json({ 
          success: false,
          error: 'Failed to send OTP'
        });
      }
    });
  } catch (error) {
    console.error('❌ Send OTP error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error'
    });
  }
});

// Verify OTP
router.post('/verify-otp', (req, res) => {
  try {
    const { phone, otp } = req.body;
    
    if (!phone || !otp) {
      return res.status(400).json({ 
        success: false,
        error: 'Phone number and OTP are required'
      });
    }

    const otpData = otpStore.get(phone);
    
    if (!otpData) {
      return res.status(400).json({ 
        success: false,
        error: 'OTP not found or expired'
      });
    }

    // Check if OTP is expired
    if (Date.now() > otpData.expiresAt) {
      otpStore.delete(phone);
      return res.status(400).json({ 
        success: false,
        error: 'OTP has expired'
      });
    }

    // Check attempts (prevent brute force)
    if (otpData.attempts >= 3) {
      otpStore.delete(phone);
      return res.status(400).json({ 
        success: false,
        error: 'Too many failed attempts'
      });
    }

    // Verify OTP
    if (otpData.otp !== otp) {
      otpData.attempts += 1;
      return res.status(400).json({ 
        success: false,
        error: 'Invalid OTP'
      });
    }

    // Mark as verified
    otpData.verified = true;
    
    console.log(`✅ OTP verified for ${phone}`);
    res.json({
      success: true,
      message: 'OTP verified successfully'
    });
  } catch (error) {
    console.error('❌ Verify OTP error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error'
    });
  }
});

// Reset password
router.post('/reset-password', async (req, res) => {
  try {
    const { phone, newPassword } = req.body;
    
    if (!phone || !newPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Phone number and new password are required'
      });
    }

    // Validate password
    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 8 characters long'
      });
    }

    const otpData = otpStore.get(phone);
    
    if (!otpData || !otpData.verified) {
      return res.status(400).json({ 
        success: false,
        error: 'OTP verification required'
      });
    }

    const db = getDatabase();
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password
    db.run(
      'UPDATE users SET password = ? WHERE phone = ?',
      [hashedPassword, phone],
      function(err) {
        if (err) {
          console.error('❌ Failed to update password:', err);
          return res.status(500).json({ 
            success: false,
            error: 'Failed to update password'
          });
        }
        
        if (this.changes === 0) {
          return res.status(404).json({ 
            success: false,
            error: 'User not found'
          });
        }
        
        // Clear OTP data
        otpStore.delete(phone);
        
        console.log(`✅ Password reset for phone ${phone}`);
        res.json({
          success: true,
          message: 'Password reset successfully'
        });
      }
    );
  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error'
    });
  }
});

module.exports = router;