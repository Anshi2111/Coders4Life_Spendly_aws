const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const https = require('https');
const querystring = require('querystring');
const url = require('url');
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
    console.log('📱 SMS function called for phone:', phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2'));
    
    // Production SMS API configuration
    const SMS_API_KEY = process.env.SMS_API_KEY;
    const SMS_SENDER_ID = process.env.SMS_SENDER_ID || 'SPNDLY';
    const SMS_API_URL = process.env.SMS_API_URL;
    
    console.log('🔧 SMS Config check:', {
      hasApiKey: !!SMS_API_KEY,
      hasApiUrl: !!SMS_API_URL,
      senderId: SMS_SENDER_ID,
      nodeEnv: process.env.NODE_ENV
    });
    
    // In development, just log the OTP
    if (process.env.NODE_ENV === 'development' || !SMS_API_KEY || !SMS_API_URL) {
      console.log(`🔧 DEV MODE - OTP for ${phone}: ${otp}`);
      console.log(`📱 SMS would be sent to ${phone.startsWith('+91') ? phone : `+91${phone}`}: Your Spendly OTP is ${otp}. Valid for 5 minutes.`);
      return { success: true };
    }

    // Format phone number for India (+91)
    const formattedPhone = phone.startsWith('+91') ? phone : `+91${phone.replace(/^\+?91/, '')}`;
    
    const message = `Your Spendly OTP is ${otp}. Valid for 5 minutes. Do not share with anyone.`;
    
    console.log(`📱 Sending SMS to ${formattedPhone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')}`);
    
    // For production, integrate with actual SMS API
    const smsData = querystring.stringify({
      apikey: SMS_API_KEY,
      sender: SMS_SENDER_ID,
      numbers: formattedPhone,
      message: message,
      route: 4
    });
    
    const parsedUrl = url.parse(SMS_API_URL);
    
    return new Promise((resolve, reject) => {
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(smsData)
        }
      };
      
      const protocol = parsedUrl.protocol === 'https:' ? https : require('http');
      
      const req = protocol.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try {
            console.log('📱 SMS API Response:', data);
            const result = JSON.parse(data);
            if (res.statusCode === 200 && result.status === 'success') {
              console.log('✅ SMS sent successfully');
              resolve({ success: true });
            } else {
              console.error('❌ SMS API error:', result);
              reject(new Error(`SMS API failed: ${result.message || 'Unknown error'}`));
            }
          } catch (parseError) {
            console.error('❌ SMS response parse error:', parseError);
            console.error('❌ Raw response:', data);
            reject(new Error('Invalid SMS API response'));
          }
        });
      });
      
      req.on('error', (error) => {
        console.error('❌ SMS request error:', error);
        reject(error);
      });
      
      req.setTimeout(10000, () => {
        req.destroy();
        reject(new Error('SMS request timeout'));
      });
      
      req.write(smsData);
      req.end();
    });

  } catch (error) {
    console.error('❌ SMS sending failed:', error.message);
    throw error;
  }
};

// Register
router.post('/register', async (req, res) => {
  try {
    console.log('📥 Register request received:', { body: { ...req.body, password: '[HIDDEN]' } });
    
    const { email, password, name, phone } = req.body;
    
    if (!email || !password || !name) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ 
        error: 'Missing required fields',
        message: 'Email, password, and name are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log('❌ Invalid email format:', email);
      return res.status(400).json({ 
        error: 'Invalid email',
        message: 'Please enter a valid email address'
      });
    }

    // Validate password strength
    if (password.length < 6) {
      console.log('❌ Password too short');
      return res.status(400).json({ 
        error: 'Weak password',
        message: 'Password must be at least 6 characters long'
      });
    }

    console.log('✅ Validation passed for registration');
    const db = getDatabase();
    
    // Check if user already exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, existingUser) => {
      try {
        if (err) {
          console.error('❌ Database error during user check:', err);
          return res.status(500).json({ 
            error: 'Database error',
            message: 'Failed to check existing user: ' + err.message
          });
        }
        
        if (existingUser) {
          console.log('❌ User already exists:', email);
          return res.status(409).json({ 
            error: 'User exists',
            message: 'User with this email already exists'
          });
        }
        
        try {
          console.log('🔐 Hashing password...');
          // Hash password
          const saltRounds = 12;
          const hashedPassword = await bcrypt.hash(password, saltRounds);
          console.log('✅ Password hashed successfully');
          
          // Insert user
          db.run(
            'INSERT INTO users (email, password, name, phone) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, name, phone || null],
            function(err) {
              try {
                if (err) {
                  console.error('❌ Failed to create user:', err);
                  return res.status(500).json({ 
                    error: 'Registration failed',
                    message: 'Failed to create user account: ' + err.message
                  });
                }
                
                console.log('✅ User created with ID:', this.lastID);
                
                // Generate JWT token
                const token = jwt.sign(
                  { userId: this.lastID, email },
                  process.env.JWT_SECRET,
                  { expiresIn: '7d' }
                );
                
                console.log('✅ User registered successfully:', email);
                res.status(201).json({
                  message: 'User registered successfully',
                  token,
                  user: {
                    id: this.lastID,
                    email,
                    name,
                    phone: phone || null
                  }
                });
              } catch (tokenError) {
                console.error('❌ Token generation error:', tokenError);
                res.status(500).json({ 
                  error: 'Registration failed',
                  message: 'Failed to generate token: ' + tokenError.message
                });
              }
            }
          );
        } catch (hashError) {
          console.error('❌ Password hashing error:', hashError);
          res.status(500).json({ 
            error: 'Registration failed',
            message: 'Failed to process password: ' + hashError.message
          });
        }
      } catch (innerError) {
        console.error('❌ Inner error in register:', innerError);
        res.status(500).json({ 
          error: 'Registration failed',
          message: 'Internal error: ' + innerError.message
        });
      }
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Registration failed: ' + error.message
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
          message: 'Login failed'
        });
      }
      
      if (!user) {
        return res.status(401).json({ 
          error: 'Invalid credentials',
          message: 'Invalid email or password'
        });
      }
      
      try {
        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
          return res.status(401).json({ 
            error: 'Invalid credentials',
            message: 'Invalid email or password'
          });
        }
        
        // Generate JWT token
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
            phone: user.phone
          }
        });
      } catch (compareError) {
        console.error('❌ Password comparison error:', compareError);
        res.status(500).json({ 
          error: 'Login failed',
          message: 'Authentication error'
        });
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Login failed'
    });
  }
});

// Send OTP for password reset
router.post('/send-otp', async (req, res) => {
  try {
    console.log('📥 Send OTP request received:', { body: req.body });
    
    const { phone } = req.body;
    
    if (!phone) {
      console.log('❌ Missing phone number in request');
      return res.status(400).json({ 
        success: false,
        error: 'Phone number is required'
      });
    }

    // Validate phone number format (Indian mobile)
    const phoneRegex = /^[6-9]\d{9}$/;
    if (!phoneRegex.test(phone)) {
      console.log('❌ Invalid phone format:', phone);
      return res.status(400).json({ 
        success: false,
        error: 'Invalid phone number format'
      });
    }

    console.log('✅ Phone validation passed:', phone);
    const db = getDatabase();
    
    // Check if user exists with this phone number
    db.get('SELECT id, email FROM users WHERE phone = ?', [phone], async (err, user) => {
      try {
        if (err) {
          console.error('❌ Database error:', err);
          return res.status(500).json({ 
            success: false,
            error: 'Database error: ' + err.message
          });
        }
        
        if (!user) {
          console.log('❌ Phone number not found in database:', phone);
          return res.status(404).json({ 
            success: false,
            error: 'Phone number not registered'
          });
        }

        console.log('✅ User found for phone:', phone);

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

        console.log('✅ OTP generated and stored for:', phone);

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
      } catch (innerError) {
        console.error('❌ Inner error in send-otp:', innerError);
        res.status(500).json({ 
          success: false,
          error: 'Internal error: ' + innerError.message
        });
      }
    });
  } catch (error) {
    console.error('❌ Send OTP error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error: ' + error.message
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
  } catch (error) {
    console.error('❌ Verify OTP error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error'
    });
  }
});

// Reset password (after OTP verification)
router.post('/reset-password', (req, res) => {
  try {
    const { phone, newPassword } = req.body;
    
    if (!phone || !newPassword) {
      return res.status(400).json({ 
        success: false,
        error: 'Phone number and new password are required'
      });
    }

    // Validate password strength
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters long'
      });
    }

    const db = getDatabase();
    
    // Find user by phone
    db.get('SELECT id FROM users WHERE phone = ?', [phone], async (err, user) => {
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

      try {
        // Hash new password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        
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
            
            console.log(`✅ Password reset successfully for ${phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')}`);
            res.json({
              success: true,
              message: 'Password reset successfully'
            });
          }
        );
      } catch (hashError) {
        console.error('❌ Password hashing error:', hashError);
        res.status(500).json({ 
          success: false,
          error: 'Failed to process new password'
        });
      }
    });
  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error'
    });
  }
});

module.exports = router;