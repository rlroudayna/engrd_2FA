// src/admin/Login.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './components/AdminStyles.css';

export default function Login() {
  const [step, setStep] = useState('credentials'); // 'credentials' | 'totp'
  const [formData, setFormData] = useState({ username: '', password: '' });
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [partialToken, setPartialToken] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [warning, setWarning] = useState('');

  const { login, verifyTwoFactor, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (isAuthenticated) {
      const from = location.state?.from?.pathname || '/admin/jobs';
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, location]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    if (error) setError('');
  };

  // Step 1: submit credentials
  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const result = await login(formData.username, formData.password);
      if (result.success && result.requiresTwoFactor) {
        setPartialToken(result.partialToken);
        setStep('totp');
      } else if (result.success) {
        navigate(location.state?.from?.pathname || '/admin/jobs', { replace: true });
      } else {
        setError(result.message);
      }
    } catch {
      setError('Erreur de connexion. Veuillez réessayer.');
    } finally {
      setLoading(false);
    }
  };

  // Step 2: submit TOTP or recovery code
  const handleTwoFactor = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const result = await verifyTwoFactor(
        partialToken,
        useRecovery ? undefined : totpCode,
        useRecovery ? recoveryCode : undefined
      );
      if (result.success) {
        if (result.warning) setWarning(result.warning);
        navigate(location.state?.from?.pathname || '/admin/jobs', { replace: true });
      } else if (result.locked) {
        setError(result.message);
        setStep('credentials');
        setPartialToken(null);
      } else {
        setError(result.message + (result.attemptsLeft ? ` (${result.attemptsLeft} tentative(s) restante(s))` : ''));
      }
    } catch {
      setError('Erreur de vérification. Veuillez réessayer.');
    } finally {
      setLoading(false);
    }
  };

  if (step === 'totp') {
    return (
      <div className="login-container">
        <div className="login-form-wrapper">
          <form onSubmit={handleTwoFactor} className="login-form">
            <div className="login-header">
              <h2>Vérification 2FA</h2>
              <p>{useRecovery ? 'Entrez un code de récupération' : 'Entrez le code de votre application d\'authentification'}</p>
            </div>

            {error && <div className="error-message">{error}</div>}
            {warning && <div className="warning-message" style={{ color: '#e67e22', marginBottom: 12 }}>{warning}</div>}

            {!useRecovery ? (
              <div className="form-group">
                <label htmlFor="totpCode">Code 2FA (6 chiffres)</label>
                <input
                  type="text"
                  id="totpCode"
                  inputMode="numeric"
                  maxLength={6}
                  placeholder="000000"
                  value={totpCode}
                  onChange={e => { setTotpCode(e.target.value); if (error) setError(''); }}
                  required
                  disabled={loading}
                  autoFocus
                />
              </div>
            ) : (
              <div className="form-group">
                <label htmlFor="recoveryCode">Code de récupération</label>
                <input
                  type="text"
                  id="recoveryCode"
                  placeholder="XXXXXXXXXX"
                  value={recoveryCode}
                  onChange={e => { setRecoveryCode(e.target.value.toUpperCase()); if (error) setError(''); }}
                  required
                  disabled={loading}
                  autoFocus
                />
              </div>
            )}

            <button type="submit" className="login-button" disabled={loading}>
              {loading ? <><div className="button-spinner"></div>Vérification...</> : 'Vérifier'}
            </button>

            <button
              type="button"
              style={{ marginTop: 12, background: 'none', border: 'none', color: '#666', cursor: 'pointer', textDecoration: 'underline', fontSize: 13 }}
              onClick={() => { setUseRecovery(!useRecovery); setError(''); }}
            >
              {useRecovery ? 'Utiliser le code 2FA' : 'Utiliser un code de récupération'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="login-container">
      <div className="login-form-wrapper">
        <form onSubmit={handleLogin} className="login-form">
          <div className="login-header">
            <h2>Connexion Admin</h2>
            <p>Accédez au panneau d'administration</p>
          </div>

          {error && <div className="error-message">{error}</div>}

          <div className="form-group">
            <label htmlFor="username">Nom d'utilisateur</label>
            <input
              type="text"
              id="username"
              name="username"
              placeholder="Entrez votre nom d'utilisateur"
              value={formData.username}
              onChange={handleChange}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Mot de passe</label>
            <input
              type="password"
              id="password"
              name="password"
              placeholder="Entrez votre mot de passe"
              value={formData.password}
              onChange={handleChange}
              required
              disabled={loading}
            />
          </div>

          <button type="submit" className="login-button" disabled={loading}>
            {loading ? <><div className="button-spinner"></div>Connexion...</> : 'Se connecter'}
          </button>
        </form>
      </div>
    </div>
  );
}
