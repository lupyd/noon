import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import {
  decodeForm,
  encodeFormSubmission,
  encodeOtpRequest,
  encodeOtpVerify,
  encodeBlindSubmission,
  type FormType,
  FieldType,
  type FieldValue
} from '../proto';
import { Send, CheckCircle, AlertCircle, Lock, Mail, Shield, ChevronRight, Hash, ArrowLeft } from 'lucide-react';
import { useAuth0 } from '@auth0/auth0-react';
import * as mycrypto from '../crypto';

export const FormSubmission: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { getAccessTokenSilently, isAuthenticated, loginWithRedirect } = useAuth0();

  const [form, setForm] = useState<FormType | null>(null);
  const [values, setValues] = useState<Record<string, FieldValue>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [userEmail, setUserEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [showOtpInput, setShowOtpInput] = useState(false);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);

  // Per-form tokens stored in localStorage
  const [token, setToken] = useState<string | null>(localStorage.getItem(`noon_token_${id}`));

  const fetchForm = async () => {
    setLoading(true);
    setError(null);
    try {
      const headers: Record<string, string> = {};

      if (token) {
        headers['Authorization'] = `EmailOnly ${token}`;
      } else if (isAuthenticated) {
        try {
          const authToken = await getAccessTokenSilently();
          headers['Authorization'] = `Bearer ${authToken}`;
        } catch (e) {
          console.error("Failed to get token silently", e);
        }
      }

      const response = await fetch(`http://localhost:39210/forms/${id}`, {
        headers
      });

      if (response.status === 401 || response.status === 403) {
        setNeedsAuth(true);
        setLoading(false);
        return;
      }

      if (!response.ok) {
        throw new Error('Form not found or inaccessible');
      }

      const buffer = await response.arrayBuffer();
      const decoded = decodeForm(new Uint8Array(buffer));
      setForm(decoded);
      setNeedsAuth(false);

      // Initialize values
      const initialValues: Record<string, FieldValue> = {};
      decoded.fields.forEach((field) => {
        if (field.type === FieldType.CHECKBOX) {
          initialValues[field.name] = { boolValue: false };
        } else if (field.type === FieldType.NUMBER) {
          initialValues[field.name] = { doubleValue: 0 };
        } else {
          initialValues[field.name] = { stringValue: '' };
        }
      });
      setValues(initialValues);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchForm();
  }, [id, isAuthenticated, token]);

  const handleInputChange = (fieldName: string, value: string | number | boolean, type: keyof FieldValue) => {
    setValues(prev => ({
      ...prev,
      [fieldName]: { [type]: value }
    }));
  };

  const requestOtp = async () => {
    if (!userEmail) return;
    setIsVerifying(true);
    try {
      const encoded = encodeOtpRequest({ email: userEmail, formId: parseInt(id!) });
      const response = await fetch(`http://localhost:39210/email/request_otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-ignore
        body: encoded,
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || 'Failed to request OTP');
      }
      setShowOtpInput(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setIsVerifying(false);
    }
  };

  const verifyOtp = async () => {
    if (!userEmail || !otpCode) return;
    setIsVerifying(true);
    try {
      const encoded = encodeOtpVerify({ email: userEmail, code: otpCode, formId: parseInt(id!) });
      const response = await fetch(`http://localhost:39210/email/verify_otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-ignore
        body: encoded,
      });
      if (!response.ok) throw new Error('Invalid or expired OTP');

      const newToken = await response.text();
      setToken(newToken);
      localStorage.setItem(`noon_token_${id}`, newToken);
      setShowOtpInput(false);
      setNeedsAuth(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    const submissionPayload = {
      formId: parseInt(id!),
      values: values,
      submittedAt: Date.now(),
    };

    try {
      const encoded = encodeFormSubmission(submissionPayload);

      const pkRes = await fetch(`http://localhost:39210/forms/${id}/public_key`);
      if (!pkRes.ok) throw new Error("Failed to fetch public key");
      const { n: pubNBase64, e: pubEBase64 } = await pkRes.json();

      const publicN = mycrypto.bytesToBigIntLE(mycrypto.base64ToBytes(pubNBase64));
      const publicE = mycrypto.bytesToBigIntLE(mycrypto.base64ToBytes(pubEBase64));

      const payloadBytes = new Uint8Array(32);
      window.crypto.getRandomValues(payloadBytes);
      const mBig = mycrypto.bytesToBigIntLE(payloadBytes);

      let r = 0n;
      while (true) {
        r = mycrypto.randomBigInt(publicN);
        if (r > 0n && mycrypto.gcd(r, publicN) === 1n) break;
      }

      const r_e = mycrypto.modPow(r, publicE, publicN);
      const m_blinded = (mBig * r_e) % publicN;
      const blindedPayload = mycrypto.bigIntToBytesLE(m_blinded);

      const signRes = await fetch(`http://localhost:39210/forms/${id}/blind_sign`, {
        method: 'POST',
        headers: {
          'Authorization': isAuthenticated ? `Bearer ${await getAccessTokenSilently()}` : `EmailOnly ${token}`,
          'Content-Type': 'application/octet-stream',
        },
        // @ts-ignore
        body: blindedPayload,
      });

      if (!signRes.ok) throw new Error(await signRes.text() || "Failed to get blind signature.");

      const s_blinded_bytes = new Uint8Array(await signRes.arrayBuffer());
      const s_blinded = mycrypto.bytesToBigIntLE(s_blinded_bytes);

      const r_inv = mycrypto.modInverse(r, publicN);
      const s = (s_blinded * r_inv) % publicN;
      const signatureBytes = mycrypto.bigIntToBytesLE(s);

      const blindSubmission = {
        payload: payloadBytes,
        signature: signatureBytes,
        submission: encoded,
      };

      const submitRes = await fetch(`http://localhost:39210/forms/${id}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: new Uint8Array(encodeBlindSubmission(blindSubmission))
      });

      if (!submitRes.ok) throw new Error(await submitRes.text() || "Failed to submit form");

      setIsSubmitted(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (loading) return (
    <div className="loading-state animate-fade-in" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
      <div className="spinner" style={{ width: '40px', height: '40px', border: '3px solid rgba(255,255,255,0.1)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 1s linear infinite' }}></div>
      <p style={{ marginTop: '1.5rem', color: 'var(--text-muted)' }}>Decrypting secure workspace...</p>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  if (isSubmitted) return (
    <div className="submission-success card animate-fade-in" style={{ textAlign: 'center', padding: '6rem 2rem' }}>
      <div className="success-icon-wrapper" style={{ margin: '0 auto 2.5rem', width: '80px', height: '80px', background: 'rgba(16, 185, 129, 0.1)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <CheckCircle className="success-icon" size={40} style={{ color: 'var(--success)' }} />
      </div>
      <h2 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Data Transmitted</h2>
      <p className="text-muted" style={{ fontSize: '1.125rem' }}>Your response has been sealed and recorded securely.</p>
      <button onClick={() => window.location.href = '/'} className="primary-button large" style={{ marginTop: '3.5rem' }}>
        Return home
      </button>
    </div>
  );

  if (needsAuth) return (
    <div className="auth-gate card animate-fade-in" style={{ maxWidth: '600px', margin: '4rem auto', padding: '4rem 3rem' }}>
      <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
        <div className="shield-blob" style={{ margin: '0 auto 2rem', position: 'relative', width: '64px', height: '64px' }}>
          <div style={{ position: 'absolute', inset: 0, background: 'var(--accent)', filter: 'blur(20px)', opacity: 0.4, borderRadius: '50%' }}></div>
          <Shield size={64} style={{ position: 'relative', color: 'white' }} />
        </div>
        <h2 style={{ fontSize: '2.5rem', fontWeight: 900, marginBottom: '0.5rem' }}>Secure Access</h2>
        <p className="text-muted">Verification required to view this protected form.</p>
      </div>

      <div className="auth-flow" style={{ position: 'relative' }}>
        {!showOtpInput ? (
          <form onSubmit={(e) => { e.preventDefault(); requestOtp(); }} className="animate-fade-in">
            <div className="form-group">
              <label>Institutional Email</label>
              <div style={{ position: 'relative' }}>
                <Mail size={18} style={{ position: 'absolute', left: '1.25rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="email"
                  value={userEmail}
                  onChange={(e) => setUserEmail(e.target.value)}
                  placeholder="name@company.com"
                  style={{ paddingLeft: '3.5rem' }}
                  required
                />
              </div>
            </div>
            <button
              type="submit"
              className="primary-button large"
              style={{ width: '100%' }}
              disabled={!userEmail || isVerifying}
            >
              {isVerifying ? 'Generating OTP...' : <><Send size={20} /> Request Access Key</>}
            </button>
            <div style={{ margin: '2.5rem 0', display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div style={{ flex: 1, height: '1px', background: 'var(--border)' }}></div>
              <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>OR</span>
              <div style={{ flex: 1, height: '1px', background: 'var(--border)' }}></div>
            </div>
            <button
              type="button"
              onClick={() => loginWithRedirect({ appState: { returnTo: window.location.pathname } })}
              className="secondary-button"
              style={{ width: '100%', padding: '1.25rem' }}
            >
              Log In with Foundation Account
            </button>
          </form>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); verifyOtp(); }} className="animate-fade-in">
            <button type="button" onClick={() => setShowOtpInput(false)} className="text-button" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '2rem', paddingLeft: 0 }}>
              <ArrowLeft size={16} /> Change email
            </button>
            <div className="form-group">
              <label>Authentication Code</label>
              <div style={{ position: 'relative' }}>
                <Hash size={18} style={{ position: 'absolute', left: '1.25rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value)}
                  placeholder="000000"
                  maxLength={6}
                  style={{ paddingLeft: '3.5rem', letterSpacing: '0.5em', fontWeight: 700, fontSize: '1.5rem' }}
                  required
                />
              </div>
              <p className="help-text" style={{ marginTop: '1rem' }}>Enter the 6-digit code sent to {userEmail}</p>
            </div>
            <button
              type="submit"
              className="primary-button large"
              style={{ width: '100%' }}
              disabled={otpCode.length < 6 || isVerifying}
            >
              {isVerifying ? 'Authenticating...' : <><ChevronRight size={20} /> Verify & Access</>}
            </button>
          </form>
        )}
      </div>

      {error && <div className="error-message" style={{ marginTop: '2.5rem', fontSize: '0.875rem' }}>{error}</div>}
    </div>
  );

  return (
    <div className="form-submission container animate-fade-in" style={{ paddingBottom: '10rem' }}>
      <div className="header-section" style={{ marginBottom: '5rem', textAlign: 'center' }}>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', marginBottom: '2rem' }}>
          <span className="badge" style={{ background: 'rgba(59, 130, 246, 0.1)', borderColor: 'rgba(59, 130, 246, 0.2)' }}><Lock size={12} /> Anonymous</span>
          <span className="badge" style={{ background: 'rgba(16, 185, 129, 0.1)', borderColor: 'rgba(16, 185, 129, 0.2)' }}><Shield size={12} /> Verified Session</span>
        </div>
        <h1 style={{ fontSize: '4.5rem', fontWeight: 900, marginBottom: '1.5rem', letterSpacing: '-0.04em' }}>{form?.name}</h1>
        <p className="description text-muted" style={{ fontSize: '1.25rem', maxWidth: '700px', margin: '0 auto', lineHeight: 1.6 }}>{form?.description}</p>
      </div>

      <form onSubmit={handleSubmit} className="submission-fields" style={{ maxWidth: '800px', margin: '0 auto' }}>
        {form?.fields.map((field, index: number) => (
          <div key={field.name} className="form-group card animate-fade-in" style={{ padding: '2.5rem' }}>
            <label style={{ fontSize: '0.875rem', marginBottom: '1.5rem', fontWeight: 800, color: 'white', display: 'flex', justifyContent: 'space-between' }}>
              <span>{field.label} {field.required && <span style={{ color: 'var(--error)' }}>*</span>}</span>
              <span style={{ opacity: 0.3, fontWeight: 400 }}>0{index + 1}</span>
            </label>

            <div className="input-wrapper">
              {field.type === FieldType.TEXTAREA ? ( // TEXTAREA
                <textarea
                  placeholder={field.placeholder || "Your detailed response..."}
                  required={field.required}
                  onChange={(e) => handleInputChange(field.name, e.target.value, 'stringValue')}
                  rows={4}
                  style={{ resize: 'vertical' }}
                />
              ) : field.type === FieldType.NUMBER ? ( // NUMBER
                <input
                  type="number"
                  placeholder={field.placeholder || "0.00"}
                  required={field.required}
                  onChange={(e) => handleInputChange(field.name, parseFloat(e.target.value), 'doubleValue')}
                />
              ) : field.type === FieldType.CHECKBOX ? ( // CHECKBOX
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '0.5rem 0' }}>
                  <input
                    type="checkbox"
                    id={`check-${field.name}`}
                    required={field.required}
                    onChange={(e) => handleInputChange(field.name, e.target.checked, 'boolValue')}
                    style={{ width: '1.5rem', height: '1.5rem', cursor: 'pointer' }}
                  />
                  <label htmlFor={`check-${field.name}`} style={{ margin: 0, textTransform: 'none', letterSpacing: 0, fontWeight: 400, cursor: 'pointer' }}>
                    I acknowledge and confirm this data point.
                  </label>
                </div>
              ) : (
                <input
                  type={field.type === FieldType.EMAIL ? 'email' : field.type === FieldType.URL ? 'url' : 'text'}
                  placeholder={field.placeholder || "Type your answer here..."}
                  required={field.required}
                  onChange={(e) => handleInputChange(field.name, e.target.value, 'stringValue')}
                />
              )}
            </div>
            {field.helpText && <p className="help-text" style={{ marginTop: '1.25rem', fontSize: '0.875rem', opacity: 0.6 }}>{field.helpText}</p>}
          </div>
        ))}

        <div style={{ marginTop: '4rem', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <button
            type="submit"
            className="primary-button large"
            disabled={isSubmitting}
            style={{ minWidth: '300px' }}
          >
            {isSubmitting ? 'Encrypting Payload...' : <><Send size={20} /> Submit Response</>}
          </button>
          <p className="text-muted" style={{ marginTop: '1.5rem', fontSize: '0.875rem' }}>
            Responses are end-to-end encrypted and immutable once sent.
          </p>
        </div>
      </form>

      {error && (
        <div className="error-message card animate-fade-in" style={{ maxWidth: '800px', margin: '2rem auto', borderColor: 'var(--error)', background: 'rgba(239, 68, 68, 0.05)' }}>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <AlertCircle color="var(--error)" />
            <span>{error}</span>
          </div>
        </div>
      )}
    </div>
  );
};
