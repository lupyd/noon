import React, { useState } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { Plus, Trash2, Send, CheckCircle, Copy, LogIn, Mail } from 'lucide-react';
import { 
  encodeForm, 
  encodeEmailVerificationRequest, 
  encodeEmailVerificationVerify, 
  type FormType, 
  FieldType 
} from '../proto';
import { SunLogo } from './logo';


interface FormFieldInput {
  type: FieldType;
  name: string;
  label: string;
  required: boolean;
  placeholder: string;
  helpText: string;
}

const FIELD_TYPES = [
  { value: FieldType.TEXT, label: 'Text' },
  { value: FieldType.TEXTAREA, label: 'Textarea' },
  { value: FieldType.NUMBER, label: 'Number' },
  { value: FieldType.SELECT, label: 'Select' },
  { value: FieldType.RADIO, label: 'Radio' },
  { value: FieldType.CHECKBOX, label: 'Checkbox' },
  { value: FieldType.DATE, label: 'Date' },
  { value: FieldType.TIME, label: 'Time' },
  { value: FieldType.EMAIL, label: 'Email' },
  { value: FieldType.URL, label: 'URL' },
];

export const FormBuilder: React.FC = () => {
  const { isAuthenticated, loginWithRedirect, isLoading, getAccessTokenSilently } = useAuth0();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [fields, setFields] = useState<FormFieldInput[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [createdFormId, setCreatedFormId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [mentionedEmails, setMentionedEmails] = useState('');
  const [emailInput, setEmailInput] = useState('');
  const [emailVerificationCode, setEmailVerificationCode] = useState('');
  const [showEmailVerifyInput, setShowEmailVerifyInput] = useState(false);
  const [emailVerifyError, setEmailVerifyError] = useState<string | null>(null);
  const [emailToken, setEmailToken] = useState<string | null>(localStorage.getItem('noon_email_token'));
  const [verifiedEmail, setVerifiedEmail] = useState<string | null>(localStorage.getItem('noon_verified_email'));

  const addField = () => {
    const fieldName = `field_${fields.length + 1}`;
    setFields([...fields, {
      type: FieldType.TEXT,
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

  const updateField = (index: number, updates: Partial<FormFieldInput>) => {
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

    if (!verifiedEmail) {
      setError('Please verify your email before creating an email-only form.');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    const mentionedEmailsArray = mentionedEmails
      .split(',')
      .map(e => e.trim())
      .filter(e => e.length > 0);

    const formPayload: FormType = {
      id: 0,
      name,
      description,
      fields: fields.map(f => ({
        type: f.type,
        name: f.name,
        label: f.label,
        required: f.required,
        placeholder: f.placeholder,
        helpText: f.helpText,
        allowedParticipants: [],
      })),
      owner: verifiedEmail || '',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      allowedParticipants: [],
      mentionedEmails: mentionedEmailsArray,
    };

    try {
      const encoded = encodeForm(formPayload);

      let headers: Record<string, string> = {
        'Content-Type': 'application/octet-stream',
      };

      if (emailToken) {
        headers['Authorization'] = `EmailOnly ${emailToken}`;
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
        // @ts-expect-error - TS complains about Uint8Array with SharedArrayBuffer
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
    if (!emailInput) {
      setEmailVerifyError('Please enter your email first');
      return;
    }
    try {
      const encoded = encodeEmailVerificationRequest({ email: emailInput });
      const response = await fetch('http://localhost:39210/email/request_verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-expect-error
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
    if (!emailInput || !emailVerificationCode) {
      setEmailVerifyError('Please enter the verification code');
      return;
    }
    try {
      const encoded = encodeEmailVerificationVerify({ email: emailInput, code: emailVerificationCode });
      const response = await fetch('http://localhost:39210/email/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        // @ts-expect-error
        body: encoded,
      });
      if (!response.ok) {
        throw new Error('Invalid verification code');
      }
      const token = await response.text();
      setVerifiedEmail(emailInput);
      setEmailToken(token);
      localStorage.setItem('noon_verified_email', emailInput);
      localStorage.setItem('noon_email_token', token);
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
    return <div className="loading card animate-fade-in" style={{ textAlign: 'center' }}>Loading authentication status...</div>;
  }

  if (!isAuthenticated && !verifiedEmail) {
    return (
      <div className="auth-required card animate-fade-in" style={{ textAlign: 'center', padding: '6rem 2rem' }}>
        <div className="noon-logo noon-logo-hero" style={{ fontSize: '4rem', marginBottom: '2rem' }}>
          <span>N</span>
          <SunLogo height={64} />
          <span>N</span>
        </div>
        <h2>Secure Creation Environment</h2>
        <p className="text-muted" style={{ marginBottom: '3rem' }}>
          Identity verification required to deploy secure forms.
        </p>
        <button onClick={() => loginWithRedirect()} className="primary-button large" style={{ width: '100%', maxWidth: '400px' }}>
          <LogIn size={20} /> Continue with Foundation Account
        </button>
        <div style={{ margin: '2.5rem 0', display: 'flex', alignItems: 'center', gap: '1rem', maxWidth: '400px', marginInline: 'auto' }}>
          <div style={{ flex: 1, height: '1px', background: 'var(--border)' }}></div>
          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>OR</span>
          <div style={{ flex: 1, height: '1px', background: 'var(--border)' }}></div>
        </div>

        <form onSubmit={(e) => { e.preventDefault(); requestEmailVerification(); }} style={{ maxWidth: '400px', margin: '0 auto' }}>
          <div className="form-group" style={{ marginBottom: '1.5rem' }}>
            <input
              type="email"
              value={emailInput}
              onChange={(e) => setEmailInput(e.target.value)}
              placeholder="Institutional Email"
              style={{ textAlign: 'center' }}
              required
            />
          </div>
          <button type="submit" className="secondary-button" style={{ width: '100%', padding: '1.25rem' }}>
            <Mail size={18} /> Request Email Access Key
          </button>
        </form>

        <div style={{ maxWidth: '400px', margin: '0 auto' }}>
          {showEmailVerifyInput && (
            <form onSubmit={(e) => { e.preventDefault(); verifyEmail(); }} className="animate-fade-in" style={{ marginTop: '2rem' }}>
              <div className="form-group" style={{ marginBottom: '1rem' }}>
                <input
                  type="text"
                  value={emailVerificationCode}
                  onChange={(e) => setEmailVerificationCode(e.target.value)}
                  placeholder="000000"
                  style={{ textAlign: 'center', fontSize: '1.5rem', letterSpacing: '0.4em' }}
                  required
                />
              </div>
              <button type="submit" className="primary-button" style={{ width: '100%' }}>
                Verify & Enter
              </button>
            </form>
          )}
          {emailVerifyError && <div className="error-message" style={{ marginTop: '1.5rem', fontSize: '0.875rem' }}>{emailVerifyError}</div>}
        </div>
      </div>
    );
  }


  if (createdFormId) {
    return (
      <div className="form-builder-success card animate-fade-in" style={{ textAlign: 'center', padding: '6rem 2rem' }}>
        <CheckCircle className="success-icon" size={64} style={{ margin: '0 auto 2rem' }} />
        <h2>Form Ready</h2>
        <p className="text-muted" style={{ marginBottom: '3rem' }}>Your form is now live and secure.</p>
        <div className="share-link-box" style={{ marginBottom: '3rem' }}>
          <code style={{ fontSize: '1.25rem' }}>{window.location.origin}/forms/{createdFormId}</code>
          <button onClick={copyLink} className="icon-button" title="Copy Link">
            <Copy size={20} />
          </button>
        </div>
        <button onClick={() => window.location.href = '/'} className="primary-button large">
          Go to Dashboard
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); handleSubmit(); }} className="form-builder animate-fade-in">
      <div className="header-section" style={{ marginBottom: '4rem' }}>
        <h1>Create New Form</h1>
        <p className="description text-muted">Initialize your secure data collection point.</p>
      </div>

      <div className="card">
        <div className="form-group">
          <label>Form Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Q2 Performance Review"
            required
          />
        </div>
        <div className="form-group">
          <label>Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Detailed instruction for respondents..."
            rows={4}
          />
        </div>

        <div className="card special-card" style={{ padding: '2.5rem' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: 0, fontSize: '1.25rem' }}>
            <Mail size={18} /> Participant Whitelist
          </h3>
          <p className="help-text" style={{ marginBottom: '1.5rem' }}>Only these emails will be allowed to participate anonymously.</p>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <input
              type="text"
              value={mentionedEmails}
              onChange={(e) => setMentionedEmails(e.target.value)}
              placeholder="team@company.com, user@example.com"
            />
            <p className="help-text">Comma-separated list of authorized respondents.</p>
          </div>
        </div>
      </div>

      <div className="fields-section" style={{ marginTop: '4rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
          <h3>Form Fields</h3>
          <span className="badge">{fields.length} Fields</span>
        </div>

        {fields && fields.map((field, index) => (
          <div key={`${index}-${field.name}`} className="field-card card animate-fade-in" style={{ padding: '1.5rem 2rem', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', gap: '2rem', alignItems: 'flex-start' }}>
              <div style={{ flex: 2 }}>
                <label>Label</label>
                <input
                  type="text"
                  value={field.label}
                  onChange={(e) => updateField(index, { label: e.target.value })}
                  style={{ background: 'transparent', borderBottom: '1px solid var(--border)', borderRadius: 0, paddingInline: 0 }}
                  required
                />
              </div>
              <div style={{ flex: 1 }}>
                <label>Type</label>
                <select
                  value={field.type}
                  onChange={(e) => updateField(index, { type: parseInt(e.target.value) })}
                  style={{ padding: '0.75rem' }}
                >
                  {FIELD_TYPES.map(type => (
                    <option key={type.value} value={type.value}>{type.label}</option>
                  ))}
                </select>
              </div>
              <div style={{ width: '80px', textAlign: 'center' }}>
                <label>Req.</label>
                <input
                  type="checkbox"
                  checked={field.required}
                  onChange={(e) => updateField(index, { required: e.target.checked })}
                  style={{ width: '1.25rem', height: '1.25rem', marginTop: '0.5rem' }}
                />
              </div>
              <div style={{ alignSelf: 'center', paddingTop: '1.5rem' }}>
                <button type="button" onClick={() => removeField(index)} className="icon-button delete-button" title="Delete Field" style={{ color: 'var(--error)', borderColor: 'rgba(239, 68, 68, 0.2)' }}>
                  <Trash2 size={18} />
                </button>
              </div>
            </div>
          </div>
        ))}

        <button type="button" onClick={addField} className="add-field-button">
          <Plus size={20} /> Add New Data Point
        </button>
      </div>

      {error && <div className="error-message animate-fade-in">{error}</div>}

      <div className="actions">
        <button
          type="submit"
          className="primary-button large"
          disabled={isSubmitting}
        >
          {isSubmitting ? 'Processing...' : <><Send size={18} /> Deploy Form</>}
        </button>
      </div>
    </form>
  );
};
