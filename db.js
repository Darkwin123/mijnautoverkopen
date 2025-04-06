const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    const connectionString = process.env.MONGODB_URI;
    
    await mongoose.connect(connectionString);
    console.log("MongoDB connected!");
  } catch (err) {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  }
};

module.exports = connectDB;