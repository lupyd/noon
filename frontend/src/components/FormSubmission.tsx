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
import { useUnifiedAuth } from '../auth';
import { API_URL } from '../config';
import * as mycrypto from '../crypto';

export const FormSubmission: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { isAuthenticated, getAuthHeaders } = useUnifiedAuth();

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
      } else {
        const globalHeaders = await getAuthHeaders();
        if (globalHeaders['Authorization']) {
          headers['Authorization'] = globalHeaders['Authorization'];
        }
      }

      const response = await fetch(`${API_URL}/forms/${id}`, {
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
          initialValues[field.id] = { fieldId: field.id, boolValue: false };
        } else if (field.type === FieldType.NUMBER) {
          initialValues[field.id] = { fieldId: field.id, doubleValue: 0 };
        } else if (field.type === FieldType.MULTI_SELECT) {
          initialValues[field.id] = { fieldId: field.id, bitmaskValue: 0 };
        } else {
          initialValues[field.id] = { fieldId: field.id, stringValue: '' };
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
    const params = new URLSearchParams(window.location.search);
    const urlToken = params.get('token');
    if (urlToken) {
      setToken(urlToken);
      localStorage.setItem(`noon_token_${id}`, urlToken);
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [id]);

  useEffect(() => {
    fetchForm();
  }, [id, isAuthenticated, token]);

  const handleInputChange = (fieldId: string, value: string | number | boolean, type: keyof FieldValue) => {
    setValues(prev => ({
      ...prev,
      [fieldId]: { ...prev[fieldId], fieldId, [type]: value }
    }));
  };

  const requestOtp = async () => {
    if (!userEmail) return;
    setIsVerifying(true);
    try {
      const encoded = encodeOtpRequest({ email: userEmail, formId: parseInt(id!) });
      const response = await fetch(`${API_URL}/email/request_otp`, {
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
      const response = await fetch(`${API_URL}/email/verify_otp`, {
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

    for (const field of form?.fields || []) {
      if (field.required && field.type === FieldType.MULTI_SELECT) {
        const val = values[field.id]?.bitmaskValue || 0;
        if (val === 0) {
          setError(`Field "${field.label}" is required.`);
          setIsSubmitting(false);
          return;
        }
      }
    }

    const submissionPayload = {
      formId: parseInt(id!),
      values: Object.values(values),
      submittedAt: Date.now(),
    };

    try {
      const encoded = encodeFormSubmission(submissionPayload);

      const pkRes = await fetch(`${API_URL}/forms/${id}/public_key`);
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

      const signRes = await fetch(`${API_URL}/forms/${id}/blind_sign`, {
        method: 'POST',
        headers: {
          'Authorization': token ? `EmailOnly ${token}` : (await getAuthHeaders())['Authorization'] || '',
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

      const submitRes = await fetch(`${API_URL}/forms/${id}/submit`, {
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
      <div className="spinner" style={{ width: '40px', height: '40px', border: '3px solid var(--border)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 1s linear infinite' }}></div>
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
          <Shield size={64} style={{ position: 'relative', color: 'var(--text)' }} />
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
              <p className="help-text" style={{ marginTop: '1rem' }}>Enter the 6-digit code sent to {userEmail}. <br /><strong>Check your spam folder if it doesn't arrive.</strong></p>
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
        <h1 style={{ fontSize: '4.5rem', fontWeight: 900, marginBottom: '0.5rem', letterSpacing: '-0.04em' }}>{form?.name}</h1>
        <p className="owner-mention" style={{ fontSize: '1rem', marginBottom: '1.5rem', fontWeight: 600 }}>By {form?.owner?.replace('email:', '').replace('user:', '')}</p>
        <p className="description text-muted" style={{ fontSize: '1.25rem', maxWidth: '700px', margin: '0 auto', lineHeight: 1.6 }}>{form == null ? '' : form.description}</p>

        {form != null && form.deadline > 0 && (
          <div style={{ marginTop: '2rem' }}>
            <span className="badge" style={{ background: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.2)', color: 'var(--error)' }}>
              Deadline: {new Date(Number(form.deadline) * 1000).toLocaleString()}
            </span>
          </div>
        )}
      </div>

      <form onSubmit={handleSubmit} className="submission-fields" style={{ maxWidth: '600px', margin: '0 auto' }}>
        {form?.fields.map((field, index: number) => (
          <div key={field.id} className="form-group card animate-fade-in" style={{ padding: '1.5rem 2rem' }}>
            <label style={{ fontSize: '0.875rem', marginBottom: '1.5rem', fontWeight: 800, color: 'var(--text)', display: 'flex', justifyContent: 'space-between' }}>
              <span>{field.label} {field.required && <span style={{ color: 'var(--error)' }}>*</span>}</span>
              <span style={{ opacity: 0.3, fontWeight: 400 }}>0{index + 1}</span>
            </label>

            <div className="input-wrapper">
              {field.type === FieldType.TEXTAREA ? (
                <textarea
                  placeholder={field.placeholder || "Your detailed response..."}
                  required={field.required}
                  onChange={(e) => handleInputChange(field.id, e.target.value, 'stringValue')}
                  rows={4}
                  style={{ resize: 'vertical' }}
                  maxLength={field.maxLength || undefined}
                />
              ) : field.type === FieldType.NUMBER ? (
                <input
                  type="number"
                  placeholder={field.placeholder || "0.00"}
                  required={field.required}
                  onChange={(e) => handleInputChange(field.id, parseFloat(e.target.value), 'doubleValue')}
                  min={field.numberConfig?.min || undefined}
                  max={field.numberConfig?.max || undefined}
                  step={field.numberConfig?.step || undefined}
                />
              ) : field.type === FieldType.CHECKBOX ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.25rem 0' }}>
                  <input
                    type="checkbox"
                    id={`check-${field.id}`}
                    required={field.required}
                    onChange={(e) => handleInputChange(field.id, e.target.checked, 'boolValue')}
                    style={{ width: '1.25rem', height: '1.25rem', cursor: 'pointer' }}
                  />
                  <label htmlFor={`check-${field.id}`} style={{ margin: 0, textTransform: 'none', letterSpacing: 0, fontWeight: 400, cursor: 'pointer', color: 'var(--text)' }}>
                    I acknowledge and confirm this data point.
                  </label>
                </div>
              ) : field.type === FieldType.RADIO ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', padding: '0.5rem 0' }}>
                  {field.selectOptions?.options.map((opt: any) => (
                    <div key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <input
                        type="radio"
                        name={field.id}
                        value={opt.value}
                        id={`radio-${field.id}-${opt.value}`}
                        required={field.required}
                        onChange={(e) => handleInputChange(field.id, e.target.value, 'stringValue')}
                        style={{ width: '1.25rem', height: '1.25rem', cursor: 'pointer' }}
                      />
                      <label htmlFor={`radio-${field.id}-${opt.value}`} style={{ margin: 0, fontWeight: 400, cursor: 'pointer' }}>{opt.label}</label>
                    </div>
                  ))}
                </div>
              ) : field.type === FieldType.SELECT ? (
                <select
                  required={field.required}
                  onChange={(e) => handleInputChange(field.id, e.target.value, 'stringValue')}
                  style={{ width: '100%', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)' }}
                >
                  <option value="">{field.placeholder || "Select an option..."}</option>
                  {field.selectOptions?.options.map((opt: any) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              ) : field.type === FieldType.MULTI_SELECT ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', padding: '0.5rem 0' }}>
                  {field.selectOptions?.options.map((opt: any) => (
                    <div key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <input
                        type="checkbox"
                        value={opt.value}
                        id={`multi-${field.id}-${opt.value}`}
                        onChange={(e) => {
                          const currentBitmask = values[field.id]?.bitmaskValue || 0;
                          const newBitmask = e.target.checked
                            ? currentBitmask | (1 << opt.bit)
                            : currentBitmask & ~(1 << opt.bit);
                          handleInputChange(field.id, newBitmask, 'bitmaskValue');
                        }}
                        style={{ width: '1.25rem', height: '1.25rem', cursor: 'pointer' }}
                      />
                      <label htmlFor={`multi-${field.id}-${opt.value}`} style={{ margin: 0, fontWeight: 400, cursor: 'pointer' }}>{opt.label}</label>
                    </div>
                  ))}
                </div>
              ) : (
                <input
                  type={field.type === FieldType.EMAIL ? 'email' : field.type === FieldType.URL ? 'url' : field.type === FieldType.DATE ? 'date' : field.type === FieldType.TIME ? 'time' : 'text'}
                  placeholder={field.placeholder || "Type your answer here..."}
                  required={field.required}
                  onChange={(e) => handleInputChange(field.id, e.target.value, 'stringValue')}
                  maxLength={field.maxLength || undefined}
                  pattern={field.pattern || undefined}
                />
              )}
            </div>
            {field.helpText && <p className="help-text" style={{ marginTop: '0.75rem', fontSize: '0.875rem', opacity: 0.8 }}>{field.helpText}</p>}
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
            Responses are immutable once sent.
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
