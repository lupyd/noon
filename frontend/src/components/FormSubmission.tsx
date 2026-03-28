import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { decodeForm, encodeFormSubmission } from '../proto';
import { Send, CheckCircle, AlertCircle, Lock } from 'lucide-react';
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
        <p className="description">{form.description}</p>
      </div>

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
