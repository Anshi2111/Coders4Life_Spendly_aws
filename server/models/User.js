const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    trim: true,
    sparse: true // Allows multiple null values but unique non-null values
  },
  salary: {
    type: Number,
    default: 0
  },
  profile_picture: {
    type: String,
    default: null
  }
}, {
  timestamps: true // Adds createdAt and updatedAt
});

// Remove duplicate indexes - unique: true already creates indexes
// userSchema.index({ email: 1 });
// userSchema.index({ phone: 1 });

module.exports = mongoose.model('User', userSchema);