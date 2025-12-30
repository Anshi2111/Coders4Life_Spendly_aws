const express = require('express');
const { getDatabase } = require('../database/init');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get user profile
router.get('/profile', authenticateToken, (req, res) => {
  const db = getDatabase();
  
  db.get('SELECT id, email, name, phone, salary FROM users WHERE id = ?', [req.user.userId], (err, user) => {
    if (err) {
      console.error('❌ Database error:', err);
      return res.status(500).json({ 
        error: 'Database error',
        message: 'Failed to fetch user profile'
      });
    }
    
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found',
        message: 'User profile not found'
      });
    }
    
    res.json({ user });
  });
});

// Update salary
router.put('/salary', authenticateToken, (req, res) => {
  const { salary } = req.body;
  
  if (!salary || salary <= 0) {
    return res.status(400).json({ 
      error: 'Invalid salary',
      message: 'Salary must be a positive number'
    });
  }
  
  const db = getDatabase();
  
  db.run(
    'UPDATE users SET salary = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [salary, req.user.userId],
    function(err) {
      if (err) {
        console.error('❌ Failed to update salary:', err);
        return res.status(500).json({ 
          error: 'Update failed',
          message: 'Failed to update salary'
        });
      }
      
      console.log('✅ Salary updated for user:', req.user.userId);
      res.json({ 
        message: 'Salary updated successfully',
        salary 
      });
    }
  );
});

// Update profile
router.put('/profile', authenticateToken, (req, res) => {
  const { name } = req.body;
  
  if (!name || name.trim().length === 0) {
    return res.status(400).json({ 
      error: 'Invalid name',
      message: 'Name cannot be empty'
    });
  }
  
  const db = getDatabase();
  
  db.run(
    'UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [name.trim(), req.user.userId],
    function(err) {
      if (err) {
        console.error('❌ Failed to update profile:', err);
        return res.status(500).json({ 
          error: 'Update failed',
          message: 'Failed to update profile'
        });
      }
      
      console.log('✅ Profile updated for user:', req.user.userId);
      res.json({ 
        message: 'Profile updated successfully',
        name: name.trim()
      });
    }
  );
});

module.exports = router;