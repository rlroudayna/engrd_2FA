// models/AdminTwoFactor.js
// Stores 2FA data for the single admin account in MongoDB
const mongoose = require('mongoose');

const adminTwoFactorSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  totpSecret: { type: String }, // AES-256 encrypted
  twoFactorEnabled: { type: Boolean, default: false },
  pendingSecret: { type: String }, // temp secret during enrollment
  recoveryCodes: [
    {
      hash: { type: String },
      used: { type: Boolean, default: false }
    }
  ]
}, { timestamps: true });

module.exports = mongoose.model('AdminTwoFactor', adminTwoFactorSchema);
