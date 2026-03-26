// src/admin/components/TwoFactorSettings.jsx
import React, { useState, useEffect } from 'react';
import { adminClient } from '../../utils/axiosConfig';

export default function TwoFactorSettings() {
  const [status, setStatus] = useState(null); // { twoFactorEnabled, remainingRecoveryCodes }
  const [step, setStep] = useState('idle'); // 'idle' | 'enrolling' | 'disabling' | 'regenerating'
  const [qrCode, setQrCode] = useState(null);
  const [secretKey, setSecretKey] = useState(null);
  const [totpCode, setTotpCode] = useState('');
  const [password, setPassword] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => { loadStatus(); }, []);

  const loadStatus = async () => {
    try {
      const { data } = await adminClient.get('/api/auth/2fa/status');
      setStatus(data);
    } catch (e) {
      setError('Impossible de charger le statut 2FA');
    }
  };

  const startEnroll = async () => {
    setLoading(true); setError(''); setSuccess('');
    try {
      const { data } = await adminClient.post('/api/auth/2fa/enroll');
      setQrCode(data.qrCode);
      setSecretKey(data.secret);
      setStep('enrolling');
    } catch (e) {
      setError(e.response?.data?.message || 'Erreur lors de l\'initialisation');
    } finally { setLoading(false); }
  };

  const confirmEnroll = async (e) => {
    e.preventDefault();
    setLoading(true); setError('');
    try {
      const { data } = await adminClient.post('/api/auth/2fa/enroll/verify', { token: totpCode });
      setRecoveryCodes(data.recoveryCodes);
      setStep('showCodes');
      setSuccess('2FA activé avec succès !');
      loadStatus();
    } catch (e) {
      setError(e.response?.data?.message || 'Code invalide');
    } finally { setLoading(false); }
  };

  const disable2FA = async (e) => {
    e.preventDefault();
    setLoading(true); setError('');
    try {
      await adminClient.post('/api/auth/2fa/disable', { password, token: totpCode });
      setSuccess('2FA désactivé.');
      setStep('idle');
      setPassword(''); setTotpCode('');
      loadStatus();
    } catch (e) {
      setError(e.response?.data?.message || 'Erreur lors de la désactivation');
    } finally { setLoading(false); }
  };

  const regenerateCodes = async () => {
    if (!window.confirm('Tous les codes existants seront invalidés. Continuer ?')) return;
    setLoading(true); setError('');
    try {
      const { data } = await adminClient.post('/api/auth/2fa/recovery-codes/regenerate');
      setRecoveryCodes(data.recoveryCodes);
      setStep('showCodes');
      setSuccess('Nouveaux codes générés.');
      loadStatus();
    } catch (e) {
      setError(e.response?.data?.message || 'Erreur lors de la régénération');
    } finally { setLoading(false); }
  };

  if (!status) return <div>Chargement...</div>;

  return (
    <div style={{ maxWidth: 520, margin: '0 auto', padding: 24 }}>
      <h2>Authentification à deux facteurs (2FA)</h2>

      {error && <div className="error-message" style={{ marginBottom: 12 }}>{error}</div>}
      {success && <div style={{ color: 'green', marginBottom: 12 }}>{success}</div>}

      {/* ── Status banner ── */}
      <div style={{ padding: '12px 16px', borderRadius: 8, marginBottom: 20, background: status.twoFactorEnabled ? '#e8f5e9' : '#fff3e0', border: `1px solid ${status.twoFactorEnabled ? '#a5d6a7' : '#ffcc80'}` }}>
        <strong>Statut :</strong> {status.twoFactorEnabled ? '✅ Activé' : '⚠️ Désactivé'}
        {status.twoFactorEnabled && (
          <span style={{ marginLeft: 16, fontSize: 13, color: status.remainingRecoveryCodes < 3 ? 'red' : '#555' }}>
            {status.remainingRecoveryCodes} code(s) de récupération restant(s)
          </span>
        )}
      </div>

      {/* ── Idle state ── */}
      {step === 'idle' && !status.twoFactorEnabled && (
        <button className="login-button" onClick={startEnroll} disabled={loading}>
          {loading ? 'Chargement...' : 'Activer la 2FA'}
        </button>
      )}

      {step === 'idle' && status.twoFactorEnabled && (
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <button className="login-button" style={{ background: '#e74c3c' }} onClick={() => { setStep('disabling'); setError(''); }}>
            Désactiver la 2FA
          </button>
          <button className="login-button" style={{ background: '#2980b9' }} onClick={regenerateCodes} disabled={loading}>
            Régénérer les codes de récupération
          </button>
        </div>
      )}

      {/* ── Enrollment: show QR ── */}
      {step === 'enrolling' && (
        <div>
          <p>Scannez ce QR code avec Google Authenticator ou Authy :</p>
          <img src={qrCode} alt="QR Code 2FA" style={{ display: 'block', margin: '12px auto', border: '1px solid #ddd', borderRadius: 8 }} />
          <p style={{ fontSize: 12, color: '#666', textAlign: 'center' }}>
            Clé manuelle : <code style={{ background: '#f5f5f5', padding: '2px 6px', borderRadius: 4 }}>{secretKey}</code>
          </p>
          <form onSubmit={confirmEnroll}>
            <div className="form-group">
              <label>Code de confirmation (6 chiffres)</label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                placeholder="000000"
                value={totpCode}
                onChange={e => setTotpCode(e.target.value)}
                required
                autoFocus
              />
            </div>
            <button type="submit" className="login-button" disabled={loading}>
              {loading ? 'Vérification...' : 'Confirmer l\'activation'}
            </button>
          </form>
        </div>
      )}

      {/* ── Disable 2FA form ── */}
      {step === 'disabling' && (
        <form onSubmit={disable2FA}>
          <div className="form-group">
            <label>Mot de passe actuel</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} required />
          </div>
          <div className="form-group">
            <label>Code 2FA actuel</label>
            <input type="text" inputMode="numeric" maxLength={6} placeholder="000000" value={totpCode} onChange={e => setTotpCode(e.target.value)} required />
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
            <button type="submit" className="login-button" style={{ background: '#e74c3c' }} disabled={loading}>
              {loading ? 'Désactivation...' : 'Confirmer la désactivation'}
            </button>
            <button type="button" className="login-button" style={{ background: '#95a5a6' }} onClick={() => setStep('idle')}>
              Annuler
            </button>
          </div>
        </form>
      )}

      {/* ── Show recovery codes ── */}
      {step === 'showCodes' && recoveryCodes.length > 0 && (
        <div>
          <p style={{ color: '#c0392b', fontWeight: 600 }}>⚠️ Sauvegardez ces codes maintenant. Ils ne seront plus affichés.</p>
          <div style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, fontFamily: 'monospace', lineHeight: 2 }}>
            {recoveryCodes.map((code, i) => <div key={i}>{code}</div>)}
          </div>
          <button className="login-button" style={{ marginTop: 16 }} onClick={() => { setStep('idle'); setRecoveryCodes([]); }}>
            J'ai sauvegardé mes codes
          </button>
        </div>
      )}
    </div>
  );
}
