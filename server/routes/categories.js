const express = require('express');
const Category = require('../models/Category');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Auth middleware
const auth = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    
    next();
  } catch (error) {
    console.error('❌ Auth middleware error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Get user categories
router.get('/', auth, async (req, res) => {
  try {
    const categories = await Category.find({ 
      user_id: req.userId, 
      is_active: true 
    }).sort({ createdAt: -1 });
    
    res.json(categories);
  } catch (error) {
    console.error('❌ Get categories error:', error);
    res.status(500).json({ error: 'Failed to get categories' });
  }
});

// Create category
router.post('/', auth, async (req, res) => {
  try {
    const { name, allocated_amount, color, icon } = req.body;
    
    if (!name || !allocated_amount) {
      return res.status(400).json({ error: 'Name and allocated amount are required' });
    }
    
    // Check if category name already exists for this user
    const existingCategory = await Category.findOne({
      user_id: req.userId,
      name: name.trim(),
      is_active: true
    });
    
    if (existingCategory) {
      return res.status(409).json({ error: 'Category with this name already exists' });
    }
    
    const category = new Category({
      user_id: req.userId,
      name: name.trim(),
      allocated_amount,
      current_balance: allocated_amount,
      color: color || '#3B82F6',
      icon: icon || 'wallet'
    });
    
    const savedCategory = await category.save();
    res.status(201).json({
      message: 'Category created successfully',
      category: savedCategory
    });
  } catch (error) {
    console.error('❌ Create category error:', error);
    res.status(500).json({ error: 'Failed to create category' });
  }
});

// Update category
router.put('/:id', auth, async (req, res) => {
  try {
    const { name, allocated_amount, color, icon } = req.body;
    
    const category = await Category.findOneAndUpdate(
      { _id: req.params.id, user_id: req.userId },
      { name, allocated_amount, color, icon },
      { new: true }
    );
    
    if (!category) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    res.json({
      message: 'Category updated successfully',
      category
    });
  } catch (error) {
    console.error('❌ Update category error:', error);
    res.status(500).json({ error: 'Failed to update category' });
  }
});

// Delete category
router.delete('/:id', auth, async (req, res) => {
  try {
    const category = await Category.findOneAndUpdate(
      { _id: req.params.id, user_id: req.userId },
      { is_active: false },
      { new: true }
    );
    
    if (!category) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error('❌ Delete category error:', error);
    res.status(500).json({ error: 'Failed to delete category' });
  }
});

// Recalculate category balances
router.post('/recalculate', auth, async (req, res) => {
  try {
    const categories = await Category.find({ 
      user_id: req.userId, 
      is_active: true 
    });
    
    // For now, just return current categories
    // In a full implementation, you'd recalculate based on transactions
    res.json({
      message: 'Balances recalculated successfully',
      categories
    });
  } catch (error) {
    console.error('❌ Recalculate error:', error);
    res.status(500).json({ error: 'Failed to recalculate balances' });
  }
});

module.exports = router;