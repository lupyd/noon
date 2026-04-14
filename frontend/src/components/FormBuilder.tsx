import React, { useState } from 'react';
import { useUnifiedAuth } from '../auth';
import { Plus, Trash2, Send, CheckCircle, Copy, Mail } from 'lucide-react';
import {
  encodeForm,
  type FormType,
  FieldType
} from '../proto';
import { SunLogo } from './logo';
import { API_URL } from '../config';


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
  const {
    isAuthenticated,
    email: verifiedEmail,
    isInitialLoading: isLoading,
    getAuthHeaders,
    requestEmailCode,
    loginWithEmail: verifyEmailCode
  } = useUnifiedAuth();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [fields, setFields] = useState<FormFieldInput[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [createdFormId, setCreatedFormId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deadline, setDeadline] = useState('');

  const [mentionedEmails, setMentionedEmails] = useState('');
  const [emailInput, setEmailInput] = useState('');
  const [emailVerificationCode, setEmailVerificationCode] = useState('');
  const [showEmailVerifyInput, setShowEmailVerifyInput] = useState(false);
  const [emailVerifyError, setEmailVerifyError] = useState<string | null>(null);

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
    setFields(fields.filter((_, i: number) => i !== index));
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
      .map((e: string) => e.trim())
      .filter((e: string) => e.length > 0);

    if (mentionedEmailsArray.length === 0) {
      setError('At least one authorized participant email is required.');
      setIsSubmitting(false);
      return;
    }

    const formPayload: FormType = {
      id: 0,
      name,
      description,
      fields: fields.map((f: FormFieldInput) => ({
        type: f.type,
        name: f.name,
        label: f.label,
        required: f.required,
        placeholder: f.placeholder,
        helpText: f.helpText,
        allowedParticipants: [],
      })),
      owner: verifiedEmail || '',
      createdAt: Math.floor(Date.now() / 1000),
      updatedAt: Math.floor(Date.now() / 1000),
      allowedParticipants: [],
      mentionedEmails: mentionedEmailsArray,
      deadline: deadline ? Math.floor(new Date(deadline).getTime() / 1000) : 0,
    };

    try {
      const encoded = encodeForm(formPayload);

      const headers = {
        'Content-Type': 'application/octet-stream',
        ...(await getAuthHeaders())
      };

      const response = await fetch(`${API_URL}/forms/create`, {
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

  const triggerEmailRequest = async () => {
    if (!emailInput) {
      setEmailVerifyError('Please enter your email first');
      return;
    }
    try {
      await requestEmailCode(emailInput);
      setShowEmailVerifyInput(true);
    } catch (err) {
      setEmailVerifyError((err as Error).message);
    }
  };

  const triggerEmailVerify = async () => {
    if (!emailInput || !emailVerificationCode) {
      setEmailVerifyError('Please enter the verification code');
      return;
    }
    try {
      await verifyEmailCode(emailInput, emailVerificationCode);
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
        <h2>Create New Form</h2>
        <p className="text-muted" style={{ marginBottom: '3rem' }}>
          Please verify your email to continue.
        </p>

        <div style={{ maxWidth: '400px', margin: '0 auto', minHeight: '180px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          {!showEmailVerifyInput ? (
            <form onSubmit={(e) => { e.preventDefault(); triggerEmailRequest(); }} className="animate-fade-in">
              <div className="form-group" style={{ marginBottom: '1.5rem' }}>
                <input
                  type="email"
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                  placeholder="Email Address"
                  style={{ textAlign: 'center' }}
                  required
                />
              </div>
              <button type="submit" className="secondary-button" style={{ width: '100%', padding: '1.25rem' }}>
                <Mail size={18} /> Send Verification Code
              </button>
            </form>
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); triggerEmailVerify(); }} className="animate-fade-in">
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
                Enter the 6-digit code sent to<br/>
                <strong style={{ color: 'var(--text)' }}>{emailInput}</strong>
                <br/>
                <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>(Don't forget to check your spam folder)</span>
              </p>
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
              <button type="submit" className="primary-button" style={{ width: '100%', padding: '1.125rem' }}>
                Verify & Enter
              </button>
              <button 
                type="button" 
                onClick={() => setShowEmailVerifyInput(false)} 
                className="text-button" 
                style={{ marginTop: '1rem', width: '100%', fontSize: '0.875rem' }}
              >
                Back to Email
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
        <p className="success-badge" style={{ color: 'var(--success)', fontWeight: 700, marginBottom: '1rem' }}>Invitations sent to the participants</p>
        <p className="text-muted" style={{ marginBottom: '3rem' }}>Your form is now live and secure.</p>
        <div className="share-link-box" style={{ marginBottom: '3rem' }}>
          <code style={{ fontSize: '1.25rem' }}>{window.location.origin}/forms/{createdFormId}</code>
          <button onClick={copyLink} className="icon-button" title="Copy Link">
            <Copy size={20} />
          </button>
        </div>
        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
          <button onClick={() => window.location.href = '/'} className="secondary-button large">
            Go to Dashboard
          </button>
          <button onClick={() => window.location.href = `/forms/${createdFormId}/results`} className="primary-button large">
            View Empty Results
          </button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); handleSubmit(); }} className="form-builder animate-fade-in">
      <div className="header-section" style={{ marginBottom: '4rem' }}>
        <h1>Create New Form</h1>
        <p className="description text-muted">Set up your anonymous form.</p>
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

        <div className="card special-card" style={{ padding: '2.5rem', marginTop: '1.5rem' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: 0, fontSize: '1.25rem' }}>
            <Mail size={18} /> Participant Whitelist
          </h3>
          <p className="help-text" style={{ marginBottom: '1.5rem' }}>Only these emails will be allowed to fill the form. <strong>Invitation emails with direct access links will be sent automatically.</strong></p>
          <div className="form-group" style={{ marginBottom: '1.5rem' }}>
            <input
              type="text"
              value={mentionedEmails}
              onChange={(e) => setMentionedEmails(e.target.value)}
              placeholder="team@company.com, user@example.com"
            />
            <p className="help-text">Comma-separated list of authorized respondents.</p>
          </div>

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label style={{ fontSize: '0.875rem', fontWeight: 600, display: 'block', marginBottom: '0.5rem' }}>Form Deadline (Optional)</label>
            <input
              type="datetime-local"
              value={deadline}
              onChange={(e) => setDeadline(e.target.value)}
              style={{ width: '100%' }}
            />
            <p className="help-text">Submissions will be disabled after this time.</p>
          </div>
        </div>
      </div>

      <div className="fields-section" style={{ marginTop: '4rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
          <h3>Form Fields</h3>
          <span className="badge">{fields.length} Fields</span>
        </div>

        {fields && fields.map((field: FormFieldInput, index: number) => (
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
          <Plus size={20} /> Add New Field
        </button>
      </div>

      {error && <div className="error-message animate-fade-in">{error}</div>}

      <div className="actions">
        <button
          type="submit"
          className="primary-button large"
          disabled={isSubmitting}
        >
          {isSubmitting ? 'Creating...' : <><Send size={18} /> Create Form</>}
        </button>
      </div>
    </form>
  );
};
