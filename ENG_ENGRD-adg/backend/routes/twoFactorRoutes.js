// routes/twoFactorRoutes.js
const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { authenticateAdmin } = require('../middleware/authMiddleware');
const AdminTwoFactor = require('../models/AdminTwoFactor');
const { encrypt, decrypt } = require('../utils/crypto');

// All 2FA routes require a valid admin JWT
router.use(authenticateAdmin);

// ── Helper: generate 8 recovery codes ──────────────────────────────────────
async function generateRecoveryCodes() {
  const plain = [];
  const hashed = [];
  for (let i = 0; i < 8; i++) {
    const code = crypto.randomBytes(5).toString('hex').toUpperCase(); // 10-char hex
    plain.push(code);
    hashed.push({ hash: await bcrypt.hash(code, 10), used: false });
  }
  return { plain, hashed };
}

// ── POST /api/auth/2fa/enroll ───────────────────────────────────────────────
// Generates a TOTP secret and returns a QR code
router.post('/enroll', async (req, res) => {
  try {
    const username = req.user.username;
    const issuer = process.env.APP_NAME || 'ENG-RND Admin';

    // Generate new TOTP secret
    const secret = speakeasy.generateSecret({
      name: `${issuer}:${username}`,
      issuer
    });

    // Store pending secret (not yet confirmed)
    await AdminTwoFactor.findOneAndUpdate(
      { username },
      { username, pendingSecret: encrypt(secret.base32), twoFactorEnabled: false },
      { upsert: true, new: true }
    );

    // Generate QR code as data URL
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json({ success: true, qrCode: qrDataUrl, secret: secret.base32 });
  } catch (err) {
    console.error('2FA enroll error:', err);
    res.status(500).json({ success: false, message: 'Erreur lors de l\'initialisation 2FA' });
  }
});

// ── POST /api/auth/2fa/enroll/verify ───────────────────────────────────────
// Confirms enrollment with a TOTP code
router.post('/enroll/verify', async (req, res) => {
  try {
    const { token } = req.body;
    const username = req.user.username;

    const record = await AdminTwoFactor.findOne({ username });
    if (!record || !record.pendingSecret) {
      return res.status(400).json({ success: false, message: 'Aucune inscription 2FA en attente' });
    }

    const secret = decrypt(record.pendingSecret);
    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });

    if (!valid) {
      return res.status(400).json({ success: false, message: 'Code TOTP invalide' });
    }

    const { plain, hashed } = await generateRecoveryCodes();

    await AdminTwoFactor.findOneAndUpdate(
      { username },
      {
        totpSecret: record.pendingSecret,
        pendingSecret: null,
        twoFactorEnabled: true,
        recoveryCodes: hashed
      }
    );

    res.json({ success: true, message: '2FA activé avec succès', recoveryCodes: plain });
  } catch (err) {
    console.error('2FA enroll/verify error:', err);
    res.status(500).json({ success: false, message: 'Erreur lors de la vérification 2FA' });
  }
});

// ── POST /api/auth/2fa/disable ─────────────────────────────────────────────
// Disables 2FA — requires current password + valid TOTP
router.post('/disable', async (req, res) => {
  try {
    const { password, token } = req.body;
    const username = req.user.username;

    // Verify password against env
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (password !== adminPassword) {
      return res.status(401).json({ success: false, message: 'Mot de passe incorrect' });
    }

    const record = await AdminTwoFactor.findOne({ username });
    if (!record || !record.twoFactorEnabled) {
      return res.status(400).json({ success: false, message: '2FA n\'est pas activé' });
    }

    const secret = decrypt(record.totpSecret);
    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });

    if (!valid) {
      return res.status(400).json({ success: false, message: 'Code TOTP invalide' });
    }

    await AdminTwoFactor.findOneAndUpdate(
      { username },
      { totpSecret: null, twoFactorEnabled: false, recoveryCodes: [] }
    );

    res.json({ success: true, message: '2FA désactivé avec succès' });
  } catch (err) {
    console.error('2FA disable error:', err);
    res.status(500).json({ success: false, message: 'Erreur lors de la désactivation 2FA' });
  }
});

// ── POST /api/auth/2fa/recovery-codes/regenerate ───────────────────────────
router.post('/recovery-codes/regenerate', async (req, res) => {
  try {
    const username = req.user.username;
    const record = await AdminTwoFactor.findOne({ username });

    if (!record || !record.twoFactorEnabled) {
      return res.status(400).json({ success: false, message: '2FA n\'est pas activé' });
    }

    const { plain, hashed } = await generateRecoveryCodes();
    await AdminTwoFactor.findOneAndUpdate({ username }, { recoveryCodes: hashed });

    res.json({ success: true, recoveryCodes: plain });
  } catch (err) {
    console.error('2FA regen error:', err);
    res.status(500).json({ success: false, message: 'Erreur lors de la régénération des codes' });
  }
});

// ── GET /api/auth/2fa/status ───────────────────────────────────────────────
router.get('/status', async (req, res) => {
  try {
    const record = await AdminTwoFactor.findOne({ username: req.user.username });
    const enabled = record?.twoFactorEnabled || false;
    const remaining = enabled ? record.recoveryCodes.filter(c => !c.used).length : 0;
    res.json({ success: true, twoFactorEnabled: enabled, remainingRecoveryCodes: remaining });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

module.exports = router;
