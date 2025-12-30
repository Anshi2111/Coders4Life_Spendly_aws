const express = require('express');
const { getDatabase } = require('../database/init');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get all categories for user
router.get('/', authenticateToken, (req, res) => {
  const db = getDatabase();
  
  db.all(
    'SELECT * FROM categories WHERE user_id = ? ORDER BY created_at ASC',
    [req.user.userId],
    (err, categories) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ 
          error: 'Database error',
          message: 'Failed to fetch categories'
        });
      }
      
      res.json({ categories: categories || [] });
    }
  );
});

// Create multiple categories (for default budget plan)
router.post('/bulk', authenticateToken, async (req, res) => {
  const { categories } = req.body;
  
  if (!categories || !Array.isArray(categories) || categories.length === 0) {
    return res.status(400).json({ 
      error: 'Invalid categories',
      message: 'Categories array is required'
    });
  }
  
  const db = getDatabase();
  
  try {
    // Get existing categories to check for duplicates
    const existingCategories = await new Promise((resolve, reject) => {
      db.all(
        'SELECT name FROM categories WHERE user_id = ?',
        [req.user.userId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows.map(row => row.name.toLowerCase()));
        }
      );
    });
    
    // Filter out categories that already exist (case-insensitive)
    const newCategories = categories.filter(category => 
      !existingCategories.includes(category.name.toLowerCase())
    );
    
    if (newCategories.length === 0) {
      return res.status(200).json({
        message: 'All categories already exist',
        categories: []
      });
    }
    
    // Start transaction
    await new Promise((resolve, reject) => {
      db.run('BEGIN TRANSACTION', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    
    const createdCategories = [];
    
    for (const category of newCategories) {
      if (!category.name || category.name.trim().length === 0) {
        throw new Error(`Category name is required`);
      }
      
      if (category.percentage && (category.percentage < 0 || category.percentage > 100)) {
        throw new Error(`Invalid percentage for ${category.name}`);
      }
      
      const result = await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO categories (user_id, name, percentage, fixed_amount, color, current_balance) 
           VALUES (?, ?, ?, ?, ?, ?)`,
          [
            req.user.userId,
            category.name.trim(),
            category.percentage || 0,
            category.fixed_amount || 0,
            category.color || '#4F46E5',
            0
          ],
          function(err) {
            if (err) reject(err);
            else resolve(this.lastID);
          }
        );
      });
      
      createdCategories.push({
        id: result,
        name: category.name.trim(),
        percentage: category.percentage || 0,
        fixed_amount: category.fixed_amount || 0,
        color: category.color || '#4F46E5',
        current_balance: 0
      });
    }
    
    // Commit transaction
    await new Promise((resolve, reject) => {
      db.run('COMMIT', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    
    console.log('✅ Bulk categories created:', createdCategories.length);
    res.status(201).json({
      message: `${createdCategories.length} categories created successfully`,
      categories: createdCategories
    });
    
  } catch (error) {
    // Rollback transaction
    db.run('ROLLBACK');
    console.error('❌ Failed to create bulk categories:', error);
    res.status(500).json({ 
      error: 'Creation failed',
      message: error.message || 'Failed to create categories'
    });
  }
});

// Create category
router.post('/', authenticateToken, (req, res) => {
  const { name, percentage, fixed_amount, color } = req.body;
  
  if (!name || name.trim().length === 0) {
    return res.status(400).json({ 
      error: 'Invalid name',
      message: 'Category name is required'
    });
  }
  
  if (percentage && (percentage < 0 || percentage > 100)) {
    return res.status(400).json({ 
      error: 'Invalid percentage',
      message: 'Percentage must be between 0 and 100'
    });
  }
  
  const db = getDatabase();
  
  db.run(
    `INSERT INTO categories (user_id, name, percentage, fixed_amount, color, current_balance) 
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      req.user.userId,
      name.trim(),
      percentage || 0,
      fixed_amount || 0,
      color || '#4F46E5',
      0
    ],
    function(err) {
      if (err) {
        console.error('❌ Failed to create category:', err);
        return res.status(500).json({ 
          error: 'Creation failed',
          message: 'Failed to create category'
        });
      }
      
      console.log('✅ Category created:', name);
      res.status(201).json({
        message: 'Category created successfully',
        category: {
          id: this.lastID,
          name: name.trim(),
          percentage: percentage || 0,
          fixed_amount: fixed_amount || 0,
          color: color || '#4F46E5',
          current_balance: 0
        }
      });
    }
  );
});

// Update category
router.put('/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { name, percentage, fixed_amount, color } = req.body;
  
  if (!name || name.trim().length === 0) {
    return res.status(400).json({ 
      error: 'Invalid name',
      message: 'Category name is required'
    });
  }
  
  const db = getDatabase();
  
  db.run(
    `UPDATE categories 
     SET name = ?, percentage = ?, fixed_amount = ?, color = ?
     WHERE id = ? AND user_id = ?`,
    [
      name.trim(),
      percentage || 0,
      fixed_amount || 0,
      color || '#4F46E5',
      id,
      req.user.userId
    ],
    function(err) {
      if (err) {
        console.error('❌ Failed to update category:', err);
        return res.status(500).json({ 
          error: 'Update failed',
          message: 'Failed to update category'
        });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ 
          error: 'Category not found',
          message: 'Category not found or access denied'
        });
      }
      
      console.log('✅ Category updated:', id);
      res.json({ message: 'Category updated successfully' });
    }
  );
});

// Delete category
router.delete('/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const db = getDatabase();
  
  db.run(
    'DELETE FROM categories WHERE id = ? AND user_id = ?',
    [id, req.user.userId],
    function(err) {
      if (err) {
        console.error('❌ Failed to delete category:', err);
        return res.status(500).json({ 
          error: 'Deletion failed',
          message: 'Failed to delete category'
        });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ 
          error: 'Category not found',
          message: 'Category not found or access denied'
        });
      }
      
      console.log('✅ Category deleted:', id);
      res.json({ message: 'Category deleted successfully' });
    }
  );
});

// Recalculate balances based on salary
router.post('/recalculate', authenticateToken, (req, res) => {
  const db = getDatabase();
  
  // Get user salary
  db.get('SELECT salary FROM users WHERE id = ?', [req.user.userId], (err, user) => {
    if (err) {
      console.error('❌ Database error:', err);
      return res.status(500).json({ 
        error: 'Database error',
        message: 'Failed to fetch user salary'
      });
    }
    
    if (!user || !user.salary) {
      return res.status(400).json({ 
        error: 'No salary set',
        message: 'Please set your salary first'
      });
    }
    
    // Get all categories
    db.all(
      'SELECT * FROM categories WHERE user_id = ?',
      [req.user.userId],
      (err, categories) => {
        if (err) {
          console.error('❌ Database error:', err);
          return res.status(500).json({ 
            error: 'Database error',
            message: 'Failed to fetch categories'
          });
        }
        
        // Calculate new balances
        const updates = categories.map(category => {
          let newBalance = 0;
          if (category.percentage > 0) {
            newBalance = (user.salary * category.percentage) / 100;
          } else if (category.fixed_amount > 0) {
            newBalance = category.fixed_amount;
          }
          
          return new Promise((resolve, reject) => {
            db.run(
              'UPDATE categories SET current_balance = ? WHERE id = ?',
              [newBalance, category.id],
              (err) => {
                if (err) reject(err);
                else resolve();
              }
            );
          });
        });
        
        Promise.all(updates)
          .then(() => {
            console.log('✅ Category balances recalculated');
            res.json({ message: 'Balances recalculated successfully' });
          })
          .catch(err => {
            console.error('❌ Failed to update balances:', err);
            res.status(500).json({ 
              error: 'Update failed',
              message: 'Failed to recalculate balances'
            });
          });
      }
    );
  });
});

module.exports = router;