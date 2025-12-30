const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = './server/database.sqlite';

console.log('🔍 Checking users in database...');

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    return;
  }
  console.log('✅ Connected to database');
});

// Check all users
db.all('SELECT id, email, name, phone, created_at FROM users', (err, users) => {
  if (err) {
    console.error('❌ Query failed:', err);
    return;
  }
  
  console.log(`\n📊 Found ${users.length} users:`);
  console.log('=' .repeat(80));
  
  if (users.length === 0) {
    console.log('No users found in database');
  } else {
    users.forEach((user, index) => {
      console.log(`${index + 1}. ID: ${user.id}`);
      console.log(`   Email: ${user.email}`);
      console.log(`   Name: ${user.name || 'N/A'}`);
      console.log(`   Phone: ${user.phone || '❌ NOT SET'}`);
      console.log(`   Created: ${user.created_at}`);
      console.log('-'.repeat(40));
    });
  }
  
  // Check if any users have phone numbers
  const usersWithPhone = users.filter(u => u.phone);
  const usersWithoutPhone = users.filter(u => !u.phone);
  
  console.log(`\n📈 Summary:`);
  console.log(`✅ Users with phone: ${usersWithPhone.length}`);
  console.log(`❌ Users without phone: ${usersWithoutPhone.length}`);
  
  if (usersWithoutPhone.length > 0) {
    console.log(`\n⚠️  Users without phone numbers cannot use forgot password feature!`);
    console.log(`💡 Solution: Register a new account with phone number or update existing users`);
  }
  
  db.close();
});