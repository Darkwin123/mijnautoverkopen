const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    // Replace this with your MongoDB connection string
    const connectionString = process.env.MONGODB_URI;
    
    await mongoose.connect(connectionString, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('MongoDB connected!');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

module.exports = connectDB;