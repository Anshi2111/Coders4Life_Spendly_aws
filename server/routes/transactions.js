const express = require('express');
const Transaction = require('../models/Transaction');
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

// Get user transactions
router.get('/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 50, status, category_id } = req.query;
    
    const filter = { user_id: req.userId };
    if (status) filter.status = status;
    if (category_id) filter.category_id = category_id;
    
    const transactions = await Transaction.find(filter)
      .populate('category_id', 'name color')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await Transaction.countDocuments(filter);
    
    res.json({
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('❌ Get transactions error:', error);
    res.status(500).json({ error: 'Failed to get transactions' });
  }
});

// Create transaction (initiate payment)
router.post('/', auth, async (req, res) => {
  try {
    const { category_id, amount, merchant_name, merchant_upi, note } = req.body;
    
    if (!category_id || !amount || !merchant_name) {
      return res.status(400).json({ 
        error: 'Category, amount, and merchant name are required' 
      });
    }
    
    // Verify category belongs to user
    const category = await Category.findOne({
      _id: category_id,
      user_id: req.userId,
      is_active: true
    });
    
    if (!category) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    // Check if sufficient balance
    if (amount > category.current_balance) {
      return res.status(400).json({ 
        error: 'Insufficient balance in category',
        available: category.current_balance,
        requested: amount
      });
    }
    
    const transaction = new Transaction({
      user_id: req.userId,
      category_id,
      amount,
      merchant_name: merchant_name.trim(),
      merchant_upi: merchant_upi?.trim(),
      note: note?.trim(),
      status: 'pending'
    });
    
    const savedTransaction = await transaction.save();
    
    res.status(201).json({
      message: 'Transaction created successfully',
      transaction: savedTransaction
    });
  } catch (error) {
    console.error('❌ Create transaction error:', error);
    res.status(500).json({ error: 'Failed to create transaction' });
  }
});

// Update transaction status
router.put('/:id/status', auth, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['pending', 'success', 'failed', 'cancelled'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const transaction = await Transaction.findOne({
      _id: req.params.id,
      user_id: req.userId
    });
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    // If marking as success, deduct from category balance
    if (status === 'success' && transaction.status === 'pending') {
      await Category.findByIdAndUpdate(
        transaction.category_id,
        { $inc: { current_balance: -transaction.amount } }
      );
    }
    
    // If marking as failed/cancelled from success, refund to category
    if ((status === 'failed' || status === 'cancelled') && transaction.status === 'success') {
      await Category.findByIdAndUpdate(
        transaction.category_id,
        { $inc: { current_balance: transaction.amount } }
      );
    }
    
    transaction.status = status;
    await transaction.save();
    
    res.json({
      message: 'Transaction status updated successfully',
      transaction
    });
  } catch (error) {
    console.error('❌ Update transaction status error:', error);
    res.status(500).json({ error: 'Failed to update transaction status' });
  }
});

// Get transaction details
router.get('/:id', auth, async (req, res) => {
  try {
    const transaction = await Transaction.findOne({
      _id: req.params.id,
      user_id: req.userId
    }).populate('category_id', 'name color');
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    res.json(transaction);
  } catch (error) {
    console.error('❌ Get transaction error:', error);
    res.status(500).json({ error: 'Failed to get transaction' });
  }
});

module.exports = router;