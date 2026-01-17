const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  category_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Category',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  merchant_name: {
    type: String,
    required: true,
    trim: true
  },
  merchant_upi: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['pending', 'success', 'failed', 'cancelled'],
    default: 'pending'
  },
  payment_method: {
    type: String,
    default: 'UPI'
  },
  note: {
    type: String,
    trim: true
  },
  transaction_reference: {
    type: String,
    trim: true
  }
}, {
  timestamps: true
});

// Indexes for better query performance
transactionSchema.index({ user_id: 1, createdAt: -1 });
transactionSchema.index({ category_id: 1, status: 1 });
transactionSchema.index({ status: 1 });

module.exports = mongoose.model('Transaction', transactionSchema);