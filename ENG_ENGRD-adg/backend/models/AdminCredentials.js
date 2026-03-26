// models/AdminCredentials.js
const mongoose = require('mongoose');

const adminCredentialsSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true }, // bcrypt hash
}, { timestamps: true });

module.exports = mongoose.model('AdminCredentials', adminCredentialsSchema);
