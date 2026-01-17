const express = require('express');
const User = require('../models/User');
const auth = require('../middleware/auth');

const router = express.Router();

// Get user profile
router.get('/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('❌ Get profile error:', error);
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// Update user profile
router.put('/profile', auth, async (req, res) => {
  try {
    const { name, phone } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { name, phone },
      { new: true, select: '-password' }
    );
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (error) {
    console.error('❌ Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Update salary
router.put('/salary', auth, async (req, res) => {
  try {
    const { salary } = req.body;
    
    if (!salary || salary <= 0) {
      return res.status(400).json({ error: 'Valid salary amount required' });
    }
    
    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { salary },
      { new: true, select: '-password' }
    );
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      message: 'Salary updated successfully',
      user: updatedUser
    });
  } catch (error) {
    console.error('❌ Update salary error:', error);
    res.status(500).json({ error: 'Failed to update salary' });
  }
});

module.exports = router;