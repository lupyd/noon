import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { decodeForm, encodeFormSubmission, encodeOtpRequest, encodeOtpVerify, encodeEmailVerificationRequest, encodeEmailVerificationVerify } from '../proto';
import { Send, CheckCircle, AlertCircle, Lock, Mail, Shield } from 'lucide-react';
import { useAuth0 } from '@auth0/auth0-react';
import * as mycrypto from '../crypto';

export const FormSubmission: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { getAccessTokenSilently, isAuthenticated, loginWithRedirect } = useAuth0();
  const [form, setForm] = useState<any>(null);
  const [values, setValues] = useState<Record<string, any>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [userEmail, setUserEmail] = useState('');
  const [verifiedEmail, setVerifiedEmail] = useState<string | null>(null);
  const [emailVerifyCode, setEmailVerifyCode] = useState('');
  const [showEmailVerify, setShowEmailVerify] = useState(false);
  const [otpCode, setOtpCode] = useState('');
  const [showOtpInput, setShowOtpInput] = useState(false);
  const [otpVerified, setOtpVerified] = useState(false);

  useEffect(() => {
    const fetchForm = async () => {
      try {
        const response = await fetch(`http://localhost:39210/forms/${id}`);
        if (!response.ok) {
          throw new Error('Form not found or failed to load');
        }
        const buffer = await response.arrayBuffer();
        const decoded = decodeForm(new Uint8Array(buffer));
        setForm(decoded);
        
        // Initialize values
        const initialValues: Record<string, any> = {};
        decoded.fields.forEach((field: any) => {
          if (field.type === 6) { // CHECKBOX
            initialValues[field.name] = { boolValue: false };
          } else if (field.type === 2) { // NUMBER
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

    fetchForm();
  }, [id]);

  const handleInputChange = (fieldName: string, value: any, type: string) => {
    setValues(prev => ({
      ...prev,
      [fieldName]: { [type]: value }
    }));
  };

  const requestEmailVerification = async () => {
    if (!userEmail) return;
    try {
      const encoded = encodeEmailVerificationRequest({ email: userEmail });
      const response = await fetch('http://localhost:39210/email/request_verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-ignore
        body: encoded,
      });
      if (!response.ok) throw new Error('Failed to send verification email');
      setShowEmailVerify(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const verifyEmail = async () => {
    if (!userEmail || !emailVerifyCode) return;
    try {
      const encoded = encodeEmailVerificationVerify({ email: userEmail, code: emailVerifyCode });
      const response = await fetch('http://localhost:39210/email/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-ignore
        body: encoded,
      });
      if (!response.ok) throw new Error('Invalid verification code');
      setVerifiedEmail(userEmail);
      setShowEmailVerify(false);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const requestOtp = async () => {
    if (!verifiedEmail) return;
    try {
      const encoded = encodeOtpRequest({ email: verifiedEmail, formId: parseInt(id!) });
      const response = await fetch(`http://localhost:39210/forms/${id}/request_otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-ignore
        body: encoded,
      });
      if (!response.ok) throw new Error('Failed to request OTP');
      setShowOtpInput(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const verifyOtp = async () => {
    if (!verifiedEmail || !otpCode) return;
    try {
      const encoded = encodeOtpVerify({ email: verifiedEmail, code: otpCode, formId: parseInt(id!) });
      const response = await fetch(`http://localhost:39210/forms/${id}/verify_otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-ignore
        body: encoded,
      });
      if (!response.ok) throw new Error('Invalid OTP');
      setOtpVerified(true);
    } catch (err) {
      setError((err as Error).message);
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
      username: '', // Defaulting to empty for now
    };

    try {
      const encoded = encodeFormSubmission(submissionPayload);

      if (form.is_anonymous) {
        if (!isAuthenticated) {
          loginWithRedirect({ appState: { returnTo: window.location.pathname } });
          return;
        }

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

        const token = await getAccessTokenSilently();
        const signRes = await fetch(`http://localhost:39210/forms/${id}/blind_sign`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/octet-stream',
          },
          // @ts-ignore - TS complains about Uint8Array with SharedArrayBuffer
          body: blindedPayload,
        });

        if (!signRes.ok) throw new Error(await signRes.text() || "Failed to get blind signature. Are you allowed to participate?");
        
        const s_blinded_bytes = new Uint8Array(await signRes.arrayBuffer());
        const s_blinded = mycrypto.bytesToBigIntLE(s_blinded_bytes);

        const r_inv = mycrypto.modInverse(r, publicN);
        const s = (s_blinded * r_inv) % publicN;
        const signatureBytes = mycrypto.bigIntToBytesLE(s);

        const submitRes = await fetch(`http://localhost:39210/forms/${id}/submit_blind`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            payload: mycrypto.bytesToBase64(payloadBytes),
            signature: mycrypto.bytesToBase64(signatureBytes),
            submission: mycrypto.bytesToBase64(encoded),
          })
        });

        if (!submitRes.ok) throw new Error(await submitRes.text() || "Failed to submit blind form");

      } else if (form.use_email_only) {
        if (!verifiedEmail) {
          setError('Please verify your email first');
          setIsSubmitting(false);
          return;
        }
        
        if (form.requires_otp_verification && !otpVerified) {
          setError('Please verify OTP first');
          setIsSubmitting(false);
          return;
        }

        const headers: Record<string, string> = {
          'Content-Type': 'application/octet-stream',
          'Authorization': `EmailOnly ${verifiedEmail}`,
        };

        const response = await fetch(`http://localhost:39210/forms/${id}/submit`, {
          method: 'POST',
          headers,
          // @ts-ignore - TS complains about Uint8Array with SharedArrayBuffer
          body: encoded,
        });

        if (!response.ok) {
          const text = await response.text();
          throw new Error(text || 'Failed to submit form');
        }
      } else {
        const headers: Record<string, string> = {
          'Content-Type': 'application/octet-stream',
        };

        if (isAuthenticated) {
          const token = await getAccessTokenSilently();
          headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(`http://localhost:39210/forms/${id}/submit`, {
          method: 'POST',
          headers,
          // @ts-ignore - TS complains about Uint8Array with SharedArrayBuffer
          body: encoded,
        });

        if (!response.ok) {
          const text = await response.text();
          throw new Error(text || 'Failed to submit form');
        }
      }

      setIsSubmitted(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (loading) return <div className="loading">Loading form...</div>;
  if (error) return (
    <div className="error-card card animate-fade-in">
      <AlertCircle className="error-icon" />
      <h2>Error</h2>
      <p>{error}</p>
    </div>
  );
  if (isSubmitted) return (
    <div className="submission-success card animate-fade-in">
      <CheckCircle className="success-icon" />
      <h2>Submitted!</h2>
      <p>Thank you for your response. Your submission has been recorded.</p>
    </div>
  );

  return (
    <div className="form-submission animate-fade-in">
      <div className="card form-header">
        <h1>{form.name}</h1>
        {form.is_anonymous && (
          <div className="anonymous-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', background: 'var(--primary-light)', color: 'var(--primary)', padding: '0.25rem 0.75rem', borderRadius: '1rem', fontSize: '0.875rem', marginBottom: '1rem', marginTop: '0.5rem' }}>
            <Lock size={14} /> Anonymous Form (Blind Signed)
          </div>
        )}
        {form.use_email_only && (
          <div className="anonymous-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', background: 'var(--secondary-light)', color: 'var(--secondary)', padding: '0.25rem 0.75rem', borderRadius: '1rem', fontSize: '0.875rem', marginBottom: '1rem', marginTop: '0.5rem' }}>
            <Mail size={14} /> Email-Only Form
          </div>
        )}
        <p className="description">{form.description}</p>
      </div>

      {form.use_email_only && !verifiedEmail && (
        <div className="card" style={{ marginBottom: '1.5rem', border: '1px solid var(--secondary)', background: 'var(--secondary-light)' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: 0 }}>
            <Mail size={18} /> Verify Your Email
          </h3>
          {!showEmailVerify ? (
            <>
              <div className="form-group">
                <label>Your Email</label>
                <input 
                  type="email" 
                  value={userEmail} 
                  onChange={(e) => setUserEmail(e.target.value)}
                  placeholder="your@email.com"
                />
              </div>
              <button onClick={requestEmailVerification} className="primary-button">
                Send Verification Code
              </button>
            </>
          ) : (
            <>
              <div className="form-group">
                <label>Verification Code</label>
                <input 
                  type="text" 
                  value={emailVerifyCode} 
                  onChange={(e) => setEmailVerifyCode(e.target.value)}
                  placeholder="123456"
                />
              </div>
              <button onClick={verifyEmail} className="primary-button">
                Verify Email
              </button>
            </>
          )}
        </div>
      )}

      {form.use_email_only && verifiedEmail && form.requires_otp_verification && !otpVerified && (
        <div className="card" style={{ marginBottom: '1.5rem', border: '1px solid var(--secondary)', background: 'var(--secondary-light)' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: 0 }}>
            <Shield size={18} /> OTP Verification Required
          </h3>
          {!showOtpInput ? (
            <button onClick={requestOtp} className="primary-button">
              Request OTP
            </button>
          ) : (
            <>
              <div className="form-group">
                <label>OTP Code</label>
                <input 
                  type="text" 
                  value={otpCode} 
                  onChange={(e) => setOtpCode(e.target.value)}
                  placeholder="123456"
                />
              </div>
              <button onClick={verifyOtp} className="primary-button">
                Verify OTP
              </button>
            </>
          )}
        </div>
      )}

      <form onSubmit={handleSubmit} className="submission-fields">
        {form.fields.map((field: any) => (
          <div key={field.name} className="form-group card">
            <label>
              {field.label}
              {field.required && <span className="required">*</span>}
            </label>
            
            {field.type === 1 ? ( // TEXTAREA
              <textarea 
                placeholder={field.placeholder}
                required={field.required}
                onChange={(e) => handleInputChange(field.name, e.target.value, 'stringValue')}
              />
            ) : field.type === 2 ? ( // NUMBER
              <input 
                type="number"
                placeholder={field.placeholder}
                required={field.required}
                onChange={(e) => handleInputChange(field.name, parseFloat(e.target.value), 'doubleValue')}
              />
            ) : field.type === 6 ? ( // CHECKBOX
               <input 
                type="checkbox"
                required={field.required}
                onChange={(e) => handleInputChange(field.name, e.target.checked, 'boolValue')}
              />
            ) : (
              <input 
                type={field.type === 9 ? 'email' : field.type === 10 ? 'url' : 'text'}
                placeholder={field.placeholder}
                required={field.required}
                onChange={(e) => handleInputChange(field.name, e.target.value, 'stringValue')}
              />
            )}
            {field.helpText && <p className="help-text">{field.helpText}</p>}
          </div>
        ))}

        <div className="actions">
          <button 
            type="submit" 
            className="primary-button" 
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Submitting...' : <><Send size={18} /> Submit Response</>}
          </button>
        </div>
      </form>
    </div>
  );
};
