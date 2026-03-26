// backend/routes/authRoutes.js
const express = require('express');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const router = express.Router();
const AdminTwoFactor = require('../models/AdminTwoFactor');
const AdminCredentials = require('../models/AdminCredentials');
const { decrypt } = require('../utils/crypto');
const { authenticateAdmin } = require('../middleware/authMiddleware');

// ── In-memory partial sessions (password OK, 2FA pending) ─────────────────
const partialSessions = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of partialSessions.entries()) {
    if (val.expiresAt < now) partialSessions.delete(key);
  }
}, 5 * 60 * 1000);

// ── POST /api/auth/admin/login ─────────────────────────────────────────────
router.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Identifiants requis' });
    }

    const creds = await AdminCredentials.findOne({ username });
    if (!creds) {
      // Fallback to .env credentials if DB record doesn't exist yet
      const envUsername = process.env.ADMIN_USERNAME || 'admin';
      const envPassword = process.env.ADMIN_PASSWORD || 'admin123';
      if (username !== envUsername || password !== envPassword) {
        return res.status(401).json({ success: false, message: 'Nom d\'utilisateur ou mot de passe incorrect' });
      }
    } else if (!(await bcrypt.compare(password, creds.passwordHash))) {
      return res.status(401).json({ success: false, message: 'Nom d\'utilisateur ou mot de passe incorrect' });
    }

    // Check 2FA
    const twoFARecord = await AdminTwoFactor.findOne({ username });
    if (twoFARecord?.twoFactorEnabled) {
      const partialToken = crypto.randomBytes(32).toString('hex');
      partialSessions.set(partialToken, { username, attempts: 0, expiresAt: Date.now() + 5 * 60 * 1000 });
      return res.json({ success: true, requiresTwoFactor: true, partialToken, message: 'Veuillez entrer votre code 2FA' });
    }

    const token = jwt.sign(
      { userId: 'admin', role: 'admin', username },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );
    res.json({ success: true, requiresTwoFactor: false, message: 'Connexion réussie', token, user: { username, role: 'admin' } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Erreur serveur lors de la connexion' });
  }
});

// ── POST /api/auth/2fa/verify ──────────────────────────────────────────────
router.post('/2fa/verify', async (req, res) => {
  try {
    const { partialToken, token: totpToken, recoveryCode } = req.body;
    if (!partialToken) return res.status(400).json({ success: false, message: 'Token partiel manquant' });

    const session = partialSessions.get(partialToken);
    if (!session || session.expiresAt < Date.now()) {
      partialSessions.delete(partialToken);
      return res.status(401).json({ success: false, message: 'Session expirée, veuillez vous reconnecter' });
    }

    const { username } = session;
    const record = await AdminTwoFactor.findOne({ username });
    if (!record || !record.twoFactorEnabled) {
      return res.status(400).json({ success: false, message: '2FA non configuré' });
    }

    let verified = false;

    if (recoveryCode) {
      for (const rc of record.recoveryCodes) {
        if (!rc.used && await bcrypt.compare(recoveryCode.toUpperCase(), rc.hash)) {
          rc.used = true;
          verified = true;
          break;
        }
      }
      if (verified) {
        await record.save();
        const remaining = record.recoveryCodes.filter(c => !c.used).length;
        const warning = remaining < 3
          ? `Attention : il ne vous reste que ${remaining} code(s) de récupération. Régénérez-les dès que possible.`
          : null;
        partialSessions.delete(partialToken);
        const jwtToken = jwt.sign({ userId: 'admin', role: 'admin', username }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '24h' });
        return res.json({ success: true, token: jwtToken, user: { username, role: 'admin' }, warning });
      }
      session.attempts += 1;
    } else if (totpToken) {
      const secret = decrypt(record.totpSecret);
      verified = speakeasy.totp.verify({ secret, encoding: 'base32', token: totpToken, window: 1 });
      if (verified) {
        partialSessions.delete(partialToken);
        const jwtToken = jwt.sign({ userId: 'admin', role: 'admin', username }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '24h' });
        return res.json({ success: true, token: jwtToken, user: { username, role: 'admin' } });
      }
      session.attempts += 1;
    } else {
      return res.status(400).json({ success: false, message: 'Code TOTP ou code de récupération requis' });
    }

    if (session.attempts >= 5) {
      partialSessions.delete(partialToken);
      return res.status(401).json({ success: false, locked: true, message: 'Trop de tentatives. Veuillez recommencer la connexion.' });
    }
    res.status(401).json({ success: false, message: 'Code invalide', attemptsLeft: 5 - session.attempts });
  } catch (error) {
    console.error('2FA verify error:', error);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// ── POST /api/auth/admin/change-password ──────────────────────────────────
// Requires valid JWT + current password
router.post('/admin/change-password', authenticateAdmin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const username = req.user.username;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Mot de passe actuel et nouveau mot de passe requis' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'Le nouveau mot de passe doit contenir au moins 8 caractères' });
    }

    let creds = await AdminCredentials.findOne({ username });

    // Fallback: if no DB record yet, check against .env and create it
    if (!creds) {
      const envPassword = process.env.ADMIN_PASSWORD || 'admin123';
      if (currentPassword !== envPassword) {
        return res.status(401).json({ success: false, message: 'Mot de passe actuel incorrect' });
      }
      // Create the record now
      const envHash = await bcrypt.hash(envPassword, 12);
      creds = await AdminCredentials.create({ username, passwordHash: envHash });
    } else {
      const match = await bcrypt.compare(currentPassword, creds.passwordHash);
      if (!match) {
        return res.status(401).json({ success: false, message: 'Mot de passe actuel incorrect' });
      }
    }

    const newHash = await bcrypt.hash(newPassword, 12);
    await AdminCredentials.findOneAndUpdate({ username }, { passwordHash: newHash });

    res.json({ success: true, message: 'Mot de passe modifié avec succès' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ success: false, message: 'Erreur serveur: ' + error.message });
  }
});

// ── POST /api/auth/admin/verify ────────────────────────────────────────────
router.post('/admin/verify', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(401).json({ success: false, message: 'Token manquant' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
    res.json({ success: true, message: 'Token valide', user: { username: decoded.username, role: decoded.role } });
  } catch {
    res.status(401).json({ success: false, message: 'Token invalide ou expiré' });
  }
});

// ── POST /api/auth/admin/logout ────────────────────────────────────────────
router.post('/admin/logout', (req, res) => {
  res.json({ success: true, message: 'Déconnexion réussie' });
});

module.exports = router;
