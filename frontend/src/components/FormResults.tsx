import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { 
  decodeForm, 
  decodeFormResults, 
  type FormType, 
  type FormResultsType,
  FieldType
} from '../proto';
import { useAuth0 } from '@auth0/auth0-react';
import { Shield, LayoutGrid, Table as TableIcon, Download, ArrowLeft, Loader2, AlertCircle } from 'lucide-react';

export const FormResults: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { getAccessTokenSilently, isAuthenticated, isLoading: authLoading } = useAuth0();
  
  const [form, setForm] = useState<FormType | null>(null);
  const [results, setResults] = useState<FormResultsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    if (authLoading) return;
    if (!isAuthenticated) {
        setError("Please log in to view results.");
        setLoading(false);
        return;
    }

    setLoading(true);
    setError(null);
    try {
      const token = await getAccessTokenSilently();
      const headers = { 'Authorization': `Bearer ${token}` };

      // Fetch Form Definition
      const formRes = await fetch(`http://localhost:39210/forms/${id}`, { headers });
      if (!formRes.ok) throw new Error("Failed to fetch form definition.");
      const formBuffer = await formRes.arrayBuffer();
      const decodedForm = decodeForm(new Uint8Array(formBuffer));
      setForm(decodedForm);

      // Fetch Results
      const resultsRes = await fetch(`http://localhost:39210/forms/${id}/results`, { headers });
      if (resultsRes.status === 403) throw new Error("Access denied. Only the creator can see results.");
      if (!resultsRes.ok) throw new Error("Failed to fetch results.");
      
      const resultsBuffer = await resultsRes.arrayBuffer();
      const decodedResults = decodeFormResults(new Uint8Array(resultsBuffer));
      setResults(decodedResults);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [id, isAuthenticated, authLoading]);

  const formatValue = (fieldName: string, valueObj: any) => {
    if (!valueObj) return '-';
    if (valueObj.stringValue !== undefined) return valueObj.stringValue;
    if (valueObj.integerValue !== undefined) return valueObj.integerValue.toString();
    if (valueObj.doubleValue !== undefined) return valueObj.doubleValue.toString();
    if (valueObj.boolValue !== undefined) return valueObj.boolValue ? 'Yes' : 'No';
    return '-';
  };

  if (loading) return (
    <div className="loading-container" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
      <Loader2 className="spinner" size={48} style={{ color: 'var(--accent)', animation: 'spin 2s linear infinite' }} />
      <p style={{ marginTop: '2rem', color: 'var(--text-muted)', fontWeight: 600 }}>Deciphering encrypted submissions...</p>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  if (error) return (
    <div className="error-container card animate-fade-in" style={{ maxWidth: '600px', margin: '4rem auto', textAlign: 'center', padding: '4rem 2rem' }}>
      <AlertCircle size={64} color="var(--error)" style={{ margin: '0 auto 2rem' }} />
      <h2 style={{ fontSize: '2rem', marginBottom: '1rem' }}>Access Restricted</h2>
      <p className="text-muted" style={{ marginBottom: '3rem' }}>{error}</p>
      <Link to="/" className="primary-button">Return Home</Link>
    </div>
  );

  return (
    <div className="form-results animate-fade-in" style={{ paddingBottom: '10rem' }}>
      <div className="results-header" style={{ marginBottom: '4rem' }}>
        <Link to="/" className="text-button" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '2rem', padding: 0 }}>
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
          <div>
            <h1 style={{ fontSize: '4rem', fontWeight: 900, marginBottom: '1rem', letterSpacing: '-0.04em' }}>{form?.name}</h1>
            <p className="text-muted" style={{ fontSize: '1.25rem' }}>{results?.submissions.length || 0} secure submissions received</p>
          </div>
          <button className="secondary-button" onClick={() => window.print()} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Download size={18} /> Export Data
          </button>
        </div>
      </div>

      <div className="results-content card" style={{ padding: 0, overflowX: 'auto', border: '1px solid var(--border)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border)' }}>
              <th style={{ padding: '1.5rem 2rem', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>Timestamp</th>
              {form?.fields.map(field => (
                <th key={field.name} style={{ padding: '1.5rem 2rem', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>
                  {field.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results?.submissions.map((submission, idx) => (
              <tr key={idx} style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.2s' }} className="result-row">
                <td style={{ padding: '1.5rem 2rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                  {new Date(Number(submission.submittedAt)).toLocaleString()}
                </td>
                {form?.fields.map(field => (
                  <td key={field.name} style={{ padding: '1.5rem 2rem', fontSize: '1rem', fontWeight: 500 }}>
                    {formatValue(field.name, submission.values[field.name])}
                  </td>
                ))}
              </tr>
            ))}
            {(!results || results.submissions.length === 0) && (
              <tr>
                <td colSpan={(form?.fields.length || 0) + 1} style={{ padding: '6rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <div style={{ marginBottom: '1.5rem', opacity: 0.2 }}>
                        <TableIcon size={64} style={{ margin: '0 auto' }} />
                    </div>
                    No data points collected yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      
      <style>{`
        .result-row:hover { background: rgba(255,255,255,0.02); }
        th { white-space: nowrap; }
      `}</style>
    </div>
  );
};
