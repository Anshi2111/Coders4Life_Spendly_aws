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

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { getDatabase } = require('../database/init');

const router = express.Router();

// In-memory OTP storage (in production, use Redis or database)
const otpStore = new Map();

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Hash OTP for secure storage
const hashOTP = (otp) => {
  return crypto.createHash('sha256').update(otp).digest('hex');
};

// Send OTP via SMS (Production implementation)
const sendSMS = async (phone, otp) => {
  try {
    // Production SMS API configuration
    const SMS_API_KEY = process.env.SMS_API_KEY;
    const SMS_SENDER_ID = process.env.SMS_SENDER_ID || 'SPNDLY';
    const SMS_API_URL = process.env.SMS_API_URL;
    
    if (!SMS_API_KEY || !SMS_API_URL) {
      console.error('❌ SMS configuration missing: SMS_API_KEY or SMS_API_URL not set');
      throw new Error('SMS service not configured');
    }

    // Format phone number for India (+91)
    const formattedPhone = phone.startsWith('+91') ? phone : `+91${phone.replace(/^\+?91/, '')}`;
    
    const message = `Your Spendly OTP is ${otp}. Valid for 5 minutes. Do not share with anyone.`;
    
    console.log(`📱 Sending SMS to ${formattedPhone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')}`);
    
    // SMS API call (example for common Indian SMS providers)
    const smsPayload = {
      apikey: SMS_API_KEY,
      sender: SMS_SENDER_ID,
      numbers: formattedPhone,
      message: message,
      route: 4 // Transactional route
    };

    const response = await fetch(SMS_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(smsPayload),
      timeout: 10000 // 10 second timeout
    });

    const result = await response.json();
    
    if (!response.ok) {
      console.error('❌ SMS API error:', result);
      throw new Error(`SMS API failed: ${result.message || 'Unknown error'}`);
    }

    console.log('✅ SMS sent successfully:', result.status || 'Success');
    return { success: true };

  } catch (error) {
    console.error('❌ SMS sending failed:', error.message);
    
    // In development, log OTP for testing
    if (process.env.NODE_ENV === 'development') {
      console.log(`🔧 DEV MODE - OTP for ${phone}: ${otp}`);
      return { success: true }; // Allow development to continue
    }
    
    throw error;
  }
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
      const hashedOTP = hashOTP(otp);
      const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
      
      // Store hashed OTP securely
      otpStore.set(phone, {
        otp: hashedOTP, // Store hashed version
        expiresAt,
        attempts: 0,
        verified: false
      });

      try {
        // Send SMS
        const smsResult = await sendSMS(phone, otp);
        
        if (!smsResult.success) {
          throw new Error('SMS sending failed');
        }
        
        console.log(`✅ OTP sent to ${phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')}`);
        res.json({
          success: true,
          message: 'OTP sent successfully'
        });
      } catch (smsError) {
        console.error('❌ SMS sending failed:', smsError.message);
        
        // Remove OTP from store if SMS failed
        otpStore.delete(phone);
        
        res.status(500).json({ 
          success: false,
          error: 'Unable to send OTP. Please try again later.'
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

    // Verify OTP (compare with hashed version)
    const hashedInputOTP = hashOTP(otp);
    if (otpData.otp !== hashedInputOTP) {
      otpData.attempts += 1;
      console.log(`❌ Invalid OTP attempt for ${phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')} (${otpData.attempts}/3)`);
      return res.status(400).json({ 
        success: false,
        error: 'Invalid OTP'
      });
    }

    // Mark as verified and remove from store (one-time use)
    otpStore.delete(phone);
    console.log(`✅ OTP verified successfully for ${phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')}`);
    
    res.json({
      success: true,
      message: 'OTP verified successfully'
    });
    
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