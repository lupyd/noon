import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useUnifiedAuth } from '../auth';
import { 
  decodeUserForms, 
  type FormType 
} from '../proto';
import { 
  LayoutDashboard, 
  FileText, 
  BarChart3, 
  Plus, 
  ExternalLink,
  ChevronRight,
  Clock,
  Inbox,
  Loader2,
  AlertCircle,
  Mail
} from 'lucide-react';

export const Dashboard: React.FC = () => {
  const { isAuthenticated, getAuthHeaders, isInitialLoading, clearEmailAuth, email: userEmail } = useUnifiedAuth();
  const [forms, setForms] = useState<FormType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchForms = async () => {
    if (isInitialLoading) return;
    
    if (!isAuthenticated) {
        setError("Please log in or verify email to view your dashboard.");
        setLoading(false);
        return;
    }

    setLoading(true);
    setError(null);
    try {
      const headers = await getAuthHeaders();

      const res = await fetch('http://localhost:39210/forms', { headers });
      
      if (res.status === 401) {
          clearEmailAuth();
          throw new Error("Session expired. Please re-verify your email.");
      }
      
      if (!res.ok) throw new Error("Failed to fetch forms.");
      
      const buffer = await res.arrayBuffer();
      const decoded = decodeUserForms(new Uint8Array(buffer));
      setForms(decoded.forms);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchForms();
  }, [isAuthenticated, isInitialLoading]);

  if (loading) return (
    <div className="loading-container" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
      <Loader2 className="spinner" size={48} style={{ color: 'var(--accent)', animation: 'spin 2s linear infinite' }} />
      <p style={{ marginTop: '2rem', color: 'var(--text-muted)', fontWeight: 600 }}>Loading your secure workspace...</p>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  if (error && !forms.length) return (
    <div className="error-container card animate-fade-in" style={{ maxWidth: '600px', margin: '4rem auto', textAlign: 'center', padding: '4rem 2rem' }}>
      <AlertCircle size={64} color="var(--error)" style={{ margin: '0 auto 2rem' }} />
      <h2 style={{ fontSize: '2rem', marginBottom: '1rem' }}>Unauthorized Access</h2>
      <p className="text-muted" style={{ marginBottom: '3rem' }}>{error}</p>
      <Link to="/create" className="primary-button">Sign In / Verify Email</Link>
    </div>
  );

  return (
    <div className="dashboard animate-fade-in">
      <div className="dashboard-header" style={{ marginBottom: '4rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h1 style={{ fontSize: '4rem', fontWeight: 900, marginBottom: '1rem', letterSpacing: '-0.04em', display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <LayoutDashboard size={48} /> Dashboard
          </h1>
          <p className="text-muted" style={{ fontSize: '1.25rem' }}>
            {userEmail ? (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}><Mail size={16} /> {userEmail}</span>
            ) : "Manage your secure data collection points."}
          </p>
        </div>
        <Link to="/create" className="primary-button" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Plus size={20} /> Create New Form
        </Link>
      </div>

      <div className="dashboard-stats" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '2rem', marginBottom: '4rem' }}>
        <div className="stat-card card">
          <span className="text-muted" style={{ fontSize: '0.875rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Active Forms</span>
          <div style={{ fontSize: '2.5rem', fontWeight: 900, marginTop: '0.5rem' }}>{forms.length}</div>
        </div>
        <div className="stat-card card">
          <span className="text-muted" style={{ fontSize: '0.875rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Responses</span>
          <div style={{ fontSize: '2.5rem', fontWeight: 900, marginTop: '0.5rem' }}>-</div>
        </div>
      </div>

      <div className="forms-list-container">
        <h3 style={{ marginBottom: '2rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <FileText size={20} /> Your Deployments
        </h3>
        
        <div className="forms-grid" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {forms.map(form => (
            <div key={form.id} className="form-item-card card" style={{ padding: '2rem', transition: 'transform 0.2s, background 0.2s' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
                    <h4 style={{ fontSize: '1.5rem', margin: 0 }}>{form.name}</h4>
                    <span className="badge" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)' }}>ID: {form.id}</span>
                  </div>
                  <p className="text-muted" style={{ marginBottom: '1.5rem', maxWidth: '600px' }}>{form.description || "No description provided."}</p>
                  
                  <div style={{ display: 'flex', gap: '2rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Clock size={14} /> Created {new Date(Number(form.createdAt) * 1000).toLocaleDateString()}
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Inbox size={14} /> No responses yet
                    </span>
                  </div>
                </div>

                <div className="form-actions" style={{ display: 'flex', gap: '1rem' }}>
                  <Link to={`/forms/${form.id}`} target="_blank" className="secondary-button" style={{ padding: '0.75rem 1rem' }} title="View Public Form">
                    <ExternalLink size={18} />
                  </Link>
                  <Link to={`/forms/${form.id}/results`} className="primary-button" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 1.5rem' }}>
                    <BarChart3 size={18} /> View Results <ChevronRight size={16} />
                  </Link>
                </div>
              </div>
            </div>
          ))}

          {forms.length === 0 && (
            <div className="empty-state card" style={{ textAlign: 'center', padding: '6rem 2rem' }}>
              <div style={{ opacity: 0.2, marginBottom: '2rem' }}>
                <FileText size={64} style={{ margin: '0 auto' }} />
              </div>
              <h4 style={{ fontSize: '1.5rem', marginBottom: '1rem' }}>No forms found</h4>
              <p className="text-muted" style={{ marginBottom: '2.5rem' }}>You haven't deployed any secure forms yet.</p>
              <Link to="/create" className="secondary-button">Deploy Your First Form</Link>
            </div>
          )}
        </div>
      </div>

      <style>{`
        .form-item-card:hover {
          background: rgba(255, 255, 255, 0.02);
          transform: translateY(-2px);
          border-color: var(--accent);
        }
      `}</style>
    </div>
  );
};
