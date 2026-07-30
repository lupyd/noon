import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { TEMPLATES, type Template } from './templates';
import { Eye, ArrowRight, Sparkles } from 'lucide-react';
import { FieldType } from '../proto';

export const Templates: React.FC = () => {
  const navigate = useNavigate();
  const [previewingTemplate, setPreviewingTemplate] = useState<string | null>(null);

  const getFieldTypeLabel = (type: FieldType) => {
    switch (type) {
      case FieldType.TEXT: return 'Short Text';
      case FieldType.TEXTAREA: return 'Long Text';
      case FieldType.NUMBER: return 'Number';
      case FieldType.SELECT: return 'Dropdown';
      case FieldType.MULTI_SELECT: return 'Checkboxes';
      case FieldType.RADIO: return 'Multiple Choice';
      case FieldType.CHECKBOX: return 'Acknowledge Checkbox';
      case FieldType.DATE: return 'Date';
      case FieldType.TIME: return 'Time';
      case FieldType.EMAIL: return 'Email';
      case FieldType.URL: return 'URL';
      default: return 'Field';
    }
  };

  const handleUseTemplate = (template: Template) => {
    navigate('/create', { state: { template } });
  };

  const togglePreview = (name: string) => {
    if (previewingTemplate === name) {
      setPreviewingTemplate(null);
    } else {
      setPreviewingTemplate(name);
    }
  };

  return (
    <div className="templates-container animate-fade-in" style={{ paddingBottom: '8rem', width: '100%' }}>
      <div className="header-section" style={{ marginBottom: '4rem', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '0.5rem 1rem', borderRadius: '50px', marginBottom: '1.5rem', fontSize: '0.875rem', fontWeight: 600 }}>
          <Sparkles size={14} style={{ color: 'var(--accent)' }} /> Pre-built form templates
        </div>
        <h1 style={{ fontSize: '3.5rem', fontWeight: 900, marginBottom: '0.75rem', letterSpacing: '-0.03em' }}>Choose a Template</h1>
        <p className="description text-muted" style={{ fontSize: '1.125rem', maxWidth: '600px', margin: '0 auto' }}>
          Kickstart your anonymous form collections using one of our production-ready templates.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '2rem' }}>
        {TEMPLATES.map((tpl) => {
          const isPreviewing = previewingTemplate === tpl.name;
          return (
            <div
              key={tpl.name}
              className="card animate-fade-in"
              style={{
                display: 'flex',
                flexDirection: 'column',
                padding: '2rem',
                border: isPreviewing ? '1px solid var(--accent)' : '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                transform: isPreviewing ? 'translateY(-4px)' : 'none',
                boxShadow: isPreviewing ? '0 12px 30px rgba(0,0,0,0.1)' : 'none',
                position: 'relative',
                overflow: 'hidden'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
                <span className="badge" style={{ textTransform: 'uppercase', fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.05em' }}>
                  {tpl.category}
                </span>
                <span className="text-muted" style={{ fontSize: '0.875rem' }}>
                  {tpl.fields.length} fields
                </span>
              </div>

              <h3 style={{ fontSize: '1.5rem', fontWeight: 800, margin: '0 0 0.75rem 0', color: 'var(--text)' }}>
                {tpl.name}
              </h3>
              
              <p className="text-muted" style={{ fontSize: '0.95rem', lineHeight: 1.5, margin: '0 0 2rem 0', flex: 1 }}>
                {tpl.description}
              </p>

              {isPreviewing && (
                <div className="animate-fade-in" style={{ borderTop: '1px solid var(--border)', paddingTop: '1.5rem', marginBottom: '1.5rem' }}>
                  <p style={{ fontSize: '0.875rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--text)' }}>Template Fields:</p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '180px', overflowY: 'auto', paddingRight: '0.5rem' }}>
                    {tpl.fields.map((f) => (
                      <div key={f.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg)', padding: '0.5rem 0.75rem', borderRadius: '4px', border: '1px solid var(--border)', fontSize: '0.825rem' }}>
                        <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '60%' }}>{f.label}</span>
                        <span style={{ opacity: 0.6, fontSize: '0.75rem' }}>{getFieldTypeLabel(f.type)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', gap: '0.75rem', marginTop: 'auto' }}>
                <button
                  onClick={() => togglePreview(tpl.name)}
                  className="secondary-button"
                  style={{ flex: 1, padding: '0.75rem 1rem', fontSize: '0.875rem', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                >
                  <Eye size={16} /> {isPreviewing ? 'Hide fields' : 'Preview'}
                </button>
                
                <button
                  onClick={() => handleUseTemplate(tpl)}
                  className="primary-button"
                  style={{ flex: 1.3, padding: '0.75rem 1.25rem', fontSize: '0.875rem', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                >
                  Use template <ArrowRight size={14} />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
