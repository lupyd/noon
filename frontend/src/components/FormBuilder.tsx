import React, { useState } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { Plus, Trash2, Send, CheckCircle, Copy, LogIn } from 'lucide-react';
import { encodeForm } from '../proto';

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

    setIsSubmitting(true);
    setError(null);

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
      isAnonymous: false, // Defaulting to false for now
    };

    try {
      const encoded = encodeForm(formPayload);
      let token = '';
      try {
        token = await getAccessTokenSilently();
      } catch (e) {
        console.warn('Could not get access token implicitly', e);
      }
      
      const response = await fetch('http://localhost:39210/forms/create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'Authorization': `Bearer ${token}`,
        },
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

  if (!isAuthenticated) {
    return (
      <div className="auth-required card animate-fade-in" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <h2>Authentication Required</h2>
        <p style={{ color: 'var(--text-muted)', marginBottom: '2rem' }}>You must be logged in to create a new form.</p>
        <button onClick={() => loginWithRedirect()} className="primary-button large">
          <LogIn size={20} /> Log In with Auth0
        </button>
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
