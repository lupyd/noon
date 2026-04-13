import React, { useState } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { Plus, Trash2, Send, CheckCircle, Copy, LogIn, Mail } from 'lucide-react';
import { encodeForm, encodeEmailVerificationRequest, encodeEmailVerificationVerify } from '../proto';

interface Field {
  type: number;
  name: string;
  label: string;
  required: boolean;
  placeholder: string;
  helpText: string;
}

const FIELD_TYPES = [
  { value: 0, label: 'Text' },
  { value: 1, label: 'Textarea' },
  { value: 2, label: 'Number' },
  { value: 3, label: 'Select' },
  { value: 5, label: 'Radio' },
  { value: 6, label: 'Checkbox' },
  { value: 7, label: 'Date' },
  { value: 8, label: 'Time' },
  { value: 9, label: 'Email' },
  { value: 10, label: 'URL' },
];

export const FormBuilder: React.FC = () => {
  const { isAuthenticated, loginWithRedirect, isLoading, getAccessTokenSilently } = useAuth0();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [fields, setFields] = useState<Field[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [createdFormId, setCreatedFormId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const [useEmailOnly, setUseEmailOnly] = useState(false);
  const [mentionedEmails, setMentionedEmails] = useState('');
  const [requiresOtpVerification, setRequiresOtpVerification] = useState(false);
  const [verifiedEmail, setVerifiedEmail] = useState<string | null>(null);
  const [emailVerificationCode, setEmailVerificationCode] = useState('');
  const [showEmailVerifyInput, setShowEmailVerifyInput] = useState(false);
  const [emailVerifyError, setEmailVerifyError] = useState<string | null>(null);

  const addField = () => {
    const fieldName = `field_${fields.length + 1}`;
    setFields([...fields, {
      type: 0,
      name: fieldName,
      label: 'New Field',
      required: false,
      placeholder: '',
      helpText: '',
    }]);
  };

  const removeField = (index: number) => {
    setFields(fields.filter((_, i) => i !== index));
  };

  const updateField = (index: number, updates: Partial<Field>) => {
    const newFields = [...fields];
    newFields[index] = { ...newFields[index], ...updates };
    setFields(newFields);
  };

  const handleSubmit = async () => {
    if (!name.trim()) {
      setError('Form name is required.');
      return;
    }
    if (fields.length === 0) {
      setError('At least one field is required.');
      return;
    }

    if (useEmailOnly && !verifiedEmail) {
      setError('Please verify your email before creating an email-only form.');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    const mentionedEmailsArray = mentionedEmails
      .split(',')
      .map(e => e.trim())
      .filter(e => e.length > 0);

    const formPayload = {
      name,
      description,
      fields: fields.map(f => ({
        type: f.type,
        name: f.name,
        label: f.label,
        required: f.required,
        placeholder: f.placeholder,
        helpText: f.helpText,
      })),
      isAnonymous: false,
      useEmailOnly,
      mentionedEmails: mentionedEmailsArray,
      requiresOtpVerification: useEmailOnly && requiresOtpVerification,
    };

    try {
      const encoded = encodeForm(formPayload);
      
      let headers: Record<string, string> = {
        'Content-Type': 'application/octet-stream',
      };
      
      if (useEmailOnly && verifiedEmail) {
        headers['Authorization'] = `EmailOnly ${verifiedEmail}`;
      } else if (isAuthenticated) {
        try {
          const token = await getAccessTokenSilently();
          headers['Authorization'] = `Bearer ${token}`;
        } catch (e) {
          console.warn('Could not get access token implicitly', e);
        }
      }
      
      const response = await fetch('http://localhost:39210/forms/create', {
        method: 'POST',
        headers,
        // @ts-ignore - TS complains about Uint8Array with SharedArrayBuffer
        body: encoded,
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || 'Failed to create form');
      }

      const data = await response.json();
      setCreatedFormId(data.id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const requestEmailVerification = async () => {
    if (!verifiedEmail) {
      setEmailVerifyError('Please enter your email first');
      return;
    }
    try {
      const encoded = encodeEmailVerificationRequest({ email: verifiedEmail });
      const response = await fetch('http://localhost:39210/email/request_verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-ignore
        body: encoded,
      });
      if (!response.ok) {
        throw new Error('Failed to send verification email');
      }
      setShowEmailVerifyInput(true);
    } catch (err) {
      setEmailVerifyError((err as Error).message);
    }
  };

  const verifyEmail = async () => {
    if (!verifiedEmail || !emailVerificationCode) {
      setEmailVerifyError('Please enter the verification code');
      return;
    }
    try {
      const encoded = encodeEmailVerificationVerify({ email: verifiedEmail, code: emailVerificationCode });
      const response = await fetch('http://localhost:39210/email/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-ignore
        body: encoded,
      });
      if (!response.ok) {
        throw new Error('Invalid verification code');
      }
      setShowEmailVerifyInput(false);
      setEmailVerifyError(null);
    } catch (err) {
      setEmailVerifyError((err as Error).message);
    }
  };

  const copyLink = () => {
    if (createdFormId) {
      const link = `${window.location.origin}/forms/${createdFormId}`;
      navigator.clipboard.writeText(link);
      alert('Link copied to clipboard!');
    }
  };

  if (isLoading) {
    return <div className="loading card" style={{ padding: '2rem', textAlign: 'center' }}>Loading authentication status...</div>;
  }

  if (!isAuthenticated && !useEmailOnly) {
    return (
      <div className="auth-required card animate-fade-in" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <h2>Create a Form</h2>
        <p style={{ color: 'var(--text-muted)', marginBottom: '2rem' }}>
          Log in with Auth0 or use email-only mode below.
        </p>
        <button onClick={() => loginWithRedirect()} className="primary-button large">
          <LogIn size={20} /> Log In with Auth0
        </button>
        <div style={{ marginTop: '2rem', paddingTop: '2rem', borderTop: '1px solid var(--border)' }}>
          <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>Or use email-only mode:</p>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input 
              type="checkbox" 
              checked={useEmailOnly} 
              onChange={(e) => setUseEmailOnly(e.target.checked)} 
            />
            Use email-only authentication
          </label>
        </div>
      </div>
    );
  }

  if (useEmailOnly && !verifiedEmail) {
    return (
      <div className="auth-required card animate-fade-in" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <h2>Verify Your Email</h2>
        <p style={{ color: 'var(--text-muted)', marginBottom: '2rem' }}>
          Enter your email to create forms without Auth0.
        </p>
        <div className="form-group" style={{ maxWidth: '400px', margin: '0 auto 1.5rem' }}>
          <input 
            type="email" 
            value={verifiedEmail || ''} 
            onChange={(e) => setVerifiedEmail(e.target.value)}
            placeholder="your@email.com"
          />
        </div>
        <button onClick={requestEmailVerification} className="primary-button large">
          <Mail size={20} /> Send Verification Code
        </button>
        {showEmailVerifyInput && (
          <div style={{ marginTop: '2rem' }}>
            <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>Enter verification code:</p>
            <div className="form-group" style={{ maxWidth: '300px', margin: '0 auto 1rem' }}>
              <input 
                type="text" 
                value={emailVerificationCode} 
                onChange={(e) => setEmailVerificationCode(e.target.value)}
                placeholder="123456"
              />
            </div>
            <button onClick={verifyEmail} className="secondary-button">
              Verify
            </button>
          </div>
        )}
        {emailVerifyError && <div className="error-message" style={{ marginTop: '1rem' }}>{emailVerifyError}</div>}
        <div style={{ marginTop: '2rem' }}>
          <button onClick={() => { setUseEmailOnly(false); setVerifiedEmail(null); }} className="text-button">
            Back to Auth0 login
          </button>
        </div>
      </div>
    );
  }

  if (createdFormId) {
    return (
      <div className="form-builder-success card animate-fade-in">
        <CheckCircle className="success-icon" />
        <h2>Form Created Successfully!</h2>
        <p>Your form is now live. Share the link below with others to collect responses.</p>
        <div className="share-link-box">
          <code>{window.location.origin}/forms/{createdFormId}</code>
          <button onClick={copyLink} className="icon-button" title="Copy Link">
            <Copy size={18} />
          </button>
        </div>
        <button onClick={() => window.location.href = '/'} className="primary-button">
          Go to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="form-builder">
      <h1>Create New Form</h1>
      
      <div className="card">
        <div className="form-group">
          <label>Form Name</label>
          <input 
            type="text" 
            value={name} 
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Feedback Form"
          />
        </div>
        <div className="form-group">
          <label>Description</label>
          <textarea 
            value={description} 
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What is this form about?"
          />
        </div>

        <div className="card" style={{ marginTop: '1rem', border: '1px solid var(--primary)', background: 'var(--primary-light)' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: 0 }}>
            <Mail size={18} /> Email-Only Mode
          </h3>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', cursor: 'pointer' }}>
            <input 
              type="checkbox" 
              checked={useEmailOnly} 
              onChange={(e) => setUseEmailOnly(e.target.checked)} 
            />
            Use email-only authentication (no Auth0 required)
          </label>
          
          {useEmailOnly && (
            <>
              <div className="form-group">
                <label>Allowed Emails (comma-separated)</label>
                <input 
                  type="text" 
                  value={mentionedEmails} 
                  onChange={(e) => setMentionedEmails(e.target.value)}
                  placeholder="alice@example.com, bob@example.com"
                />
                <p className="help-text">Only these emails will be able to submit this form.</p>
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '1rem', cursor: 'pointer' }}>
                <input 
                  type="checkbox" 
                  checked={requiresOtpVerification} 
                  onChange={(e) => setRequiresOtpVerification(e.target.checked)} 
                />
                Require OTP verification before submission
              </label>
            </>
          )}
        </div>
      </div>

      <div className="fields-section">
        <h3>Fields</h3>
        {fields.map((field, index) => (
          <div key={index} className="field-card card">
            <div className="field-header">
              <input 
                type="text" 
                value={field.label} 
                onChange={(e) => updateField(index, { label: e.target.value })}
                className="label-input"
              />
              <button onClick={() => removeField(index)} className="delete-button icon-button">
                <Trash2 size={18} />
              </button>
            </div>
            
            <div className="field-row">
              <div className="form-group sm">
                <label>Type</label>
                <select 
                  value={field.type} 
                  onChange={(e) => updateField(index, { type: parseInt(e.target.value) })}
                >
                  {FIELD_TYPES.map(type => (
                    <option key={type.value} value={type.value}>{type.label}</option>
                  ))}
                </select>
              </div>
              <div className="form-group sm">
                <label>Required</label>
                <input 
                  type="checkbox" 
                  checked={field.required} 
                  onChange={(e) => updateField(index, { required: e.target.checked })}
                />
              </div>
            </div>

            <div className="form-group sm">
              <label>Placeholder</label>
              <input 
                type="text" 
                value={field.placeholder} 
                onChange={(e) => updateField(index, { placeholder: e.target.value })}
              />
            </div>
          </div>
        ))}
        
        <button onClick={addField} className="add-field-button">
          <Plus size={20} /> Add Field
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="actions">
        <button 
          onClick={handleSubmit} 
          className="primary-button" 
          disabled={isSubmitting}
        >
          {isSubmitting ? 'Creating...' : <><Send size={18} /> Create Form</>}
        </button>
      </div>
    </div>
  );
};
