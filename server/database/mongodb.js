const mongoose = require('mongoose');

let isConnected = false;

const connectToMongoDB = async () => {
  try {
    if (isConnected) {
      console.log('✅ Already connected to MongoDB');
      return;
    }

    const MONGODB_URI = process.env.MONGODB_URI;
    
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI environment variable is not set');
    }

    console.log('🔗 Connecting to MongoDB...');
    console.log('📂 Database URI:', MONGODB_URI.replace(/\/\/.*@/, '//***:***@')); // Hide credentials in logs

    // MongoDB connection options
    const options = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      bufferMaxEntries: 0, // Disable mongoose buffering
      bufferCommands: false, // Disable mongoose buffering
    };

    await mongoose.connect(MONGODB_URI, options);
    
    isConnected = true;
    console.log('✅ Connected to MongoDB successfully');
    console.log('🗄️  Database:', mongoose.connection.db.databaseName);
    
    // Connection event listeners
    mongoose.connection.on('error', (error) => {
      console.error('❌ MongoDB connection error:', error);
      isConnected = false;
    });

    mongoose.connection.on('disconnected', () => {
      console.log('⚠️  MongoDB disconnected');
      isConnected = false;
    });

    mongoose.connection.on('reconnected', () => {
      console.log('🔄 MongoDB reconnected');
      isConnected = true;
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        console.log('🛑 MongoDB connection closed through app termination');
        process.exit(0);
      } catch (error) {
        console.error('❌ Error closing MongoDB connection:', error);
        process.exit(1);
      }
    });

  } catch (error) {
    console.error('❌ Failed to connect to MongoDB:', error.message);
    console.error('🔧 Please check:');
    console.error('   - MONGODB_URI environment variable is set');
    console.error('   - MongoDB cluster is accessible');
    console.error('   - Network connectivity');
    throw error;
  }
};

const getMongoConnection = () => {
  if (!isConnected) {
    throw new Error('MongoDB not connected. Call connectToMongoDB() first.');
  }
  return mongoose.connection;
};

module.exports = {
  connectToMongoDB,
  getMongoConnection,
  isConnected: () => isConnected
};