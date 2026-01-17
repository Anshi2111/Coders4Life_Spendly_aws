const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  allocated_amount: {
    type: Number,
    required: true,
    default: 0
  },
  current_balance: {
    type: Number,
    required: true,
    default: 0
  },
  color: {
    type: String,
    default: '#3B82F6'
  },
  icon: {
    type: String,
    default: 'wallet'
  },
  is_active: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Compound index for user categories
categorySchema.index({ user_id: 1, name: 1 }, { unique: true });
categorySchema.index({ user_id: 1, is_active: 1 });

module.exports = mongoose.model('Category', categorySchema);