// src/admin/components/ChangePassword.jsx
import React, { useState } from 'react';
import { adminClient } from '../../utils/axiosConfig';

export default function ChangePassword() {
  const [form, setForm] = useState({ currentPassword: '', newPassword: '', confirmPassword: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
    setError(''); setSuccess('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setSuccess('');

    if (form.newPassword !== form.confirmPassword) {
      return setError('Les nouveaux mots de passe ne correspondent pas');
    }
    if (form.newPassword.length < 8) {
      return setError('Le nouveau mot de passe doit contenir au moins 8 caractères');
    }

    setLoading(true);
    try {
      const { data } = await adminClient.post('/api/auth/admin/change-password', {
        currentPassword: form.currentPassword,
        newPassword: form.newPassword
      });
      setSuccess(data.message);
      setForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
    } catch (err) {
      setError(err.response?.data?.message || 'Erreur lors du changement de mot de passe');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 420, margin: '0 auto', padding: 24 }}>
      <h2>Changer le mot de passe</h2>

      {error && <div className="error-message" style={{ marginBottom: 12 }}>{error}</div>}
      {success && <div style={{ color: 'green', background: '#e8f5e9', padding: '10px 14px', borderRadius: 6, marginBottom: 12 }}>{success}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="currentPassword">Mot de passe actuel</label>
          <input
            type="password"
            id="currentPassword"
            name="currentPassword"
            value={form.currentPassword}
            onChange={handleChange}
            required
            disabled={loading}
            autoComplete="current-password"
          />
        </div>

        <div className="form-group">
          <label htmlFor="newPassword">Nouveau mot de passe</label>
          <input
            type="password"
            id="newPassword"
            name="newPassword"
            value={form.newPassword}
            onChange={handleChange}
            required
            disabled={loading}
            minLength={8}
            autoComplete="new-password"
          />
          <small style={{ color: '#888', fontSize: 12 }}>Minimum 8 caractères</small>
        </div>

        <div className="form-group">
          <label htmlFor="confirmPassword">Confirmer le nouveau mot de passe</label>
          <input
            type="password"
            id="confirmPassword"
            name="confirmPassword"
            value={form.confirmPassword}
            onChange={handleChange}
            required
            disabled={loading}
            autoComplete="new-password"
          />
        </div>

        <button type="submit" className="login-button" disabled={loading}>
          {loading ? <><div className="button-spinner"></div>Modification...</> : 'Changer le mot de passe'}
        </button>
      </form>
    </div>
  );
}
