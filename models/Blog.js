const mongoose = require("mongoose");

const BlogSchema = new mongoose.Schema({
  id: {
    type: String,
    default: function() {
      return Date.now().toString();
    }
  },
  title: {
    type: String,
    required: true
  },
  slug: {
    type: String,
    required: true,
    unique: true
  },
  content: {
    type: String,
    required: true
  },
  excerpt: String,
  featuredImage: String,
  imageAlt: String,
  author: String,
  status: {
    type: String,
    default: 'draft'
  },
  category: {
    type: String,
    default: 'algemeen'
  },
  tags: [String],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: Date
});

// Add this pre-save hook to ensure id is always set
BlogSchema.pre('save', function(next) {
  if (!this.id) {
    this.id = Date.now().toString();
  }
  next();
});

module.exports = mongoose.model("Blog", BlogSchema);