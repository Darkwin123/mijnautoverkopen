const mongoose = require('mongoose');

const InquirySchema = new mongoose.Schema({
  kenteken: String,
  merk: String,
  model: String,
  bouwjaar: Number,
  brandstof: String,
  kilometerstand: Number,
  transmissie: String,
  schade: String,
  apk: String,
  opties: [String],
  extraInfo: String,
  naam: String,
  email: String,
  telefoon: String,
  postcode: String,
  images: [{
    filename: String,
    path: String,
    size: Number
  }],
  status: {
    type: String,
    default: 'new'
  },
  notes: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: Date
});

module.exports = mongoose.model('Inquiry', InquirySchema);