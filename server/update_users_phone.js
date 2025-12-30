const sqlite3 = require('sqlite3').verbose();

const DB_PATH = './database.sqlite';

console.log('📱 Updating users with phone numbers...');

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    return;
  }
  console.log('✅ Connected to database');
});

// Phone numbers to assign to users without phone
const phoneNumbers = [
  '9876543211', // For user 2
  '9876543212', // For user 3  
  '9876543213'  // For user 4
];

// Get users without phone numbers
db.all('SELECT id, email, name FROM users WHERE phone IS NULL OR phone = ""', (err, users) => {
  if (err) {
    console.error('❌ Query failed:', err);
    db.close();
    return;
  }
  
  console.log(`\n📊 Found ${users.length} users without phone numbers:`);
  
  if (users.length === 0) {
    console.log('✅ All users already have phone numbers!');
    db.close();
    return;
  }
  
  let completed = 0;
  
  users.forEach((user, index) => {
    const phone = phoneNumbers[index] || `987654321${index + 4}`;
    
    console.log(`📱 Updating user ${user.id} (${user.email}) with phone: ${phone}`);
    
    db.run(
      'UPDATE users SET phone = ? WHERE id = ?',
      [phone, user.id],
      function(err) {
        if (err) {
          console.error(`❌ Failed to update user ${user.id}:`, err);
        } else {
          console.log(`✅ Updated user ${user.id} with phone ${phone}`);
        }
        
        completed++;
        if (completed === users.length) {
          console.log(`\n🎉 Updated ${completed} users with phone numbers!`);
          console.log('\n📋 Updated users can now use forgot password feature:');
          
          // Show updated users
          db.all('SELECT id, email, phone FROM users', (err, allUsers) => {
            if (!err) {
              allUsers.forEach(u => {
                console.log(`   ${u.email} → ${u.phone}`);
              });
            }
            db.close();
          });
        }
      }
    );
  });
});