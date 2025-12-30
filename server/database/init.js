const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = process.env.DB_PATH || './database.sqlite';

let db;

function initializeDatabase() {
  return new Promise((resolve, reject) => {
    console.log('📂 Database path:', path.resolve(DB_PATH));
    
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        console.error('❌ Database connection failed:', err.message);
        reject(err);
        return;
      }
      console.log('✅ Connected to SQLite database');
    });

    // Create tables
    const createTables = `
      -- Users table
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        phone TEXT UNIQUE,
        salary REAL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      -- Categories table
      CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        percentage REAL DEFAULT 0,
        fixed_amount REAL DEFAULT 0,
        current_balance REAL DEFAULT 0,
        color TEXT DEFAULT '#4F46E5',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      );

      -- Transactions table
      CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        category_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        merchant_upi TEXT,
        merchant_name TEXT,
        transaction_id TEXT,
        status TEXT DEFAULT 'pending',
        note TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE
      );

      -- Create indexes for better performance
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
      CREATE INDEX IF NOT EXISTS idx_categories_user_id ON categories(user_id);
      CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
      CREATE INDEX IF NOT EXISTS idx_transactions_category_id ON transactions(category_id);
    `;

    db.exec(createTables, (err) => {
      if (err) {
        console.error('❌ Failed to create tables:', err.message);
        reject(err);
        return;
      }
      console.log('✅ Database tables created/verified');
      
      // Run migrations
      runMigrations().then(() => {
        resolve();
      }).catch((migrationErr) => {
        console.error('❌ Migration failed:', migrationErr);
        resolve(); // Continue even if migrations fail
      });
    });
  });
}

// Migration function to add phone column if it doesn't exist
function runMigrations() {
  return new Promise((resolve) => {
    // Check if phone column exists
    db.all("PRAGMA table_info(users)", (err, columns) => {
      if (err) {
        console.error('❌ Failed to check table info:', err);
        resolve();
        return;
      }
      
      const hasPhoneColumn = columns.some(col => col.name === 'phone');
      
      if (!hasPhoneColumn) {
        db.run("ALTER TABLE users ADD COLUMN phone TEXT", (alterErr) => {
          if (alterErr) {
            console.error('❌ Failed to add phone column:', alterErr);
          } else {
            console.log('✅ Phone column added to users table');
          }
          resolve();
        });
      } else {
        console.log('✅ Phone column already exists');
        resolve();
      }
    });
  });
}

function getDatabase() {
  if (!db) {
    throw new Error('Database not initialized. Call initializeDatabase() first.');
  }
  return db;
}

module.exports = {
  initializeDatabase,
  getDatabase
};