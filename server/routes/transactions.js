const express = require('express');
const { getDatabase } = require('../database/init');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get all transactions for user
router.get('/', authenticateToken, (req, res) => {
  const db = getDatabase();
  
  db.all(
    `SELECT t.*, c.name as category_name, c.color as category_color
     FROM transactions t
     JOIN categories c ON t.category_id = c.id
     WHERE t.user_id = ?
     ORDER BY t.created_at DESC
     LIMIT 50`,
    [req.user.userId],
    (err, transactions) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ 
          error: 'Database error',
          message: 'Failed to fetch transactions'
        });
      }
      
      res.json({ transactions: transactions || [] });
    }
  );
});

// Create transaction (initiate payment)
router.post('/', authenticateToken, (req, res) => {
  const { category_id, amount, merchant_upi, merchant_name, note } = req.body;
  
  if (!category_id || !amount || amount <= 0) {
    return res.status(400).json({ 
      error: 'Invalid data',
      message: 'Category and valid amount are required'
    });
  }
  
  if (!merchant_upi) {
    return res.status(400).json({ 
      error: 'Invalid merchant',
      message: 'Merchant UPI ID is required'
    });
  }
  
  const db = getDatabase();
  
  // Check category balance
  db.get(
    'SELECT current_balance FROM categories WHERE id = ? AND user_id = ?',
    [category_id, req.user.userId],
    (err, category) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ 
          error: 'Database error',
          message: 'Failed to check category balance'
        });
      }
      
      if (!category) {
        return res.status(404).json({ 
          error: 'Category not found',
          message: 'Category not found or access denied'
        });
      }
      
      if (category.current_balance < amount) {
        return res.status(400).json({ 
          error: 'Insufficient balance',
          message: `Insufficient balance in category. Available: ₹${category.current_balance}`
        });
      }
      
      // Generate transaction ID
      const transactionId = 'TXN' + Date.now() + Math.random().toString(36).substr(2, 5);
      
      // Create transaction record
      db.run(
        `INSERT INTO transactions (user_id, category_id, amount, merchant_upi, merchant_name, transaction_id, status, note)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
        [
          req.user.userId,
          category_id,
          amount,
          merchant_upi,
          merchant_name || 'Unknown Merchant',
          transactionId,
          note || ''
        ],
        function(err) {
          if (err) {
            console.error('❌ Failed to create transaction:', err);
            return res.status(500).json({ 
              error: 'Transaction failed',
              message: 'Failed to create transaction record'
            });
          }
          
          // Generate UPI intent URL
          const upiUrl = `upi://pay?pa=${encodeURIComponent(merchant_upi)}&pn=${encodeURIComponent(merchant_name || 'Merchant')}&am=${amount}&cu=INR&tn=${encodeURIComponent(note || `Payment via Spendly - ${transactionId}`)}`;
          
          console.log('✅ Transaction created:', transactionId);
          res.status(201).json({
            message: 'Transaction initiated successfully',
            transaction: {
              id: this.lastID,
              transaction_id: transactionId,
              amount,
              merchant_upi,
              merchant_name: merchant_name || 'Unknown Merchant',
              status: 'pending',
              upi_url: upiUrl
            }
          });
        }
      );
    }
  );
});

// Update transaction status (after UPI payment)
router.put('/:id/status', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  
  if (!['success', 'failed', 'cancelled'].includes(status)) {
    return res.status(400).json({ 
      error: 'Invalid status',
      message: 'Status must be success, failed, or cancelled'
    });
  }
  
  const db = getDatabase();
  
  // Get transaction details
  db.get(
    'SELECT * FROM transactions WHERE id = ? AND user_id = ?',
    [id, req.user.userId],
    (err, transaction) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ 
          error: 'Database error',
          message: 'Failed to fetch transaction'
        });
      }
      
      if (!transaction) {
        return res.status(404).json({ 
          error: 'Transaction not found',
          message: 'Transaction not found or access denied'
        });
      }
      
      if (transaction.status !== 'pending') {
        return res.status(400).json({ 
          error: 'Transaction already processed',
          message: 'Transaction status cannot be changed'
        });
      }
      
      // Update transaction status
      db.run(
        'UPDATE transactions SET status = ? WHERE id = ?',
        [status, id],
        function(err) {
          if (err) {
            console.error('❌ Failed to update transaction:', err);
            return res.status(500).json({ 
              error: 'Update failed',
              message: 'Failed to update transaction status'
            });
          }
          
          // If successful, deduct from category balance
          if (status === 'success') {
            db.run(
              'UPDATE categories SET current_balance = current_balance - ? WHERE id = ?',
              [transaction.amount, transaction.category_id],
              (err) => {
                if (err) {
                  console.error('❌ Failed to update balance:', err);
                  // Rollback transaction status
                  db.run('UPDATE transactions SET status = "pending" WHERE id = ?', [id]);
                  return res.status(500).json({ 
                    error: 'Balance update failed',
                    message: 'Failed to update category balance'
                  });
                }
                
                console.log('✅ Transaction completed:', transaction.transaction_id);
                res.json({ 
                  message: 'Transaction completed successfully',
                  status 
                });
              }
            );
          } else {
            console.log('✅ Transaction cancelled/failed:', transaction.transaction_id);
            res.json({ 
              message: 'Transaction status updated',
              status 
            });
          }
        }
      );
    }
  );
});

// Get transaction by ID
router.get('/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const db = getDatabase();
  
  db.get(
    `SELECT t.*, c.name as category_name, c.color as category_color
     FROM transactions t
     JOIN categories c ON t.category_id = c.id
     WHERE t.id = ? AND t.user_id = ?`,
    [id, req.user.userId],
    (err, transaction) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ 
          error: 'Database error',
          message: 'Failed to fetch transaction'
        });
      }
      
      if (!transaction) {
        return res.status(404).json({ 
          error: 'Transaction not found',
          message: 'Transaction not found or access denied'
        });
      }
      
      res.json({ transaction });
    }
  );
});

module.exports = router;