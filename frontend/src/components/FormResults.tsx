import React, { useState, useEffect } from 'react';
import { useParams, Link, useSearchParams } from 'react-router-dom';
import {
  decodeFormResults,
  type FormType,
  type FormResultsType,
  FieldType
} from '../proto';
import { useUnifiedAuth } from '../auth';
import { Table as TableIcon, Download, ArrowLeft, Loader2, AlertCircle, ChevronLeft, ChevronRight, Lock, BarChart3 } from 'lucide-react';
import { API_URL } from '../config';
import { useTheme } from '../ThemeContext';

// Import Chart.js components
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip as ChartTooltip,
  Legend as ChartLegend
} from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ChartTooltip,
  ChartLegend
);

export const FormResults: React.FC = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const { id } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { isAuthenticated, isInitialLoading, getAuthHeaders, clearEmailAuth } = useUnifiedAuth();

  const [form, setForm] = useState<FormType | null>(null);
  const [results, setResults] = useState<FormResultsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [userTier, setUserTier] = useState('free');
  const [activeTab, setActiveTab] = useState<'table' | 'analytics'>('table');
  const [selectedSubmission, setSelectedSubmission] = useState<any>(null);

  const page = parseInt(searchParams.get('page') || '1');
  const limit = 15;
  const offset = (page - 1) * limit;

  const fetchData = async () => {
    if (isInitialLoading) return;

    if (!isAuthenticated) {
      setError("Please log in or verify email to view results.");
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const headers = await getAuthHeaders();

      // Fetch Results (includes form definition and total count)
      const resultsRes = await fetch(`${API_URL}/forms/${id}/results?limit=${limit}&offset=${offset}`, { headers });

      if (resultsRes.status === 401) {
        clearEmailAuth();
        throw new Error("Session expired. Please re-verify your email.");
      }

      if (resultsRes.status === 403) throw new Error("Access denied. Only the creator can see results.");
      if (!resultsRes.ok) throw new Error("Failed to fetch results.");

      const resultsBuffer = await resultsRes.arrayBuffer();
      const decodedResults = decodeFormResults(new Uint8Array(resultsBuffer));

      setResults(decodedResults);
      if (decodedResults.form) {
        setForm(decodedResults.form);
      }

      // Fetch subscription tier
      try {
        const subRes = await fetch(`${API_URL}/subscription/status`, { headers });
        if (subRes.ok) {
          const subData = await subRes.json();
          if (subData.tier && subData.subscription_status === 'active') {
            setUserTier(subData.tier);
          }
        }
      } catch (e) {
        console.error("Failed to fetch subscription status in results view", e);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [id, isAuthenticated, isInitialLoading, page]);

  const formatValue = (valueObj: any, field: any) => {
    if (!valueObj) return '-';

    if (field.type === 4 && valueObj.bitmaskValue !== undefined) { // 4 is FieldType.MULTI_SELECT
      if (!field.selectOptions || !field.selectOptions.options) return valueObj.bitmaskValue.toString();
      const selected = field.selectOptions.options.filter((opt: any) => (valueObj.bitmaskValue & (1 << opt.bit)) !== 0);
      return selected.map((o: any) => o.label).join(', ') || '-';
    }

    if (valueObj.stringValue !== undefined) return valueObj.stringValue;
    if (valueObj.integerValue !== undefined) return valueObj.integerValue.toString();
    if (valueObj.doubleValue !== undefined) return valueObj.doubleValue.toString();
    if (valueObj.boolValue !== undefined) return valueObj.boolValue ? 'Yes' : 'No';
    if (valueObj.bitmaskValue !== undefined) return valueObj.bitmaskValue.toString();
    return '-';
  };

  const getNumericalStats = (fieldId: string) => {
    if (!results || !results.submissions) return null;
    
    // Extract all valid numeric values for this field
    const values: number[] = [];
    results.submissions.forEach(sub => {
      const valObj = sub.values.find(v => v.fieldId === fieldId);
      if (valObj) {
        if (valObj.doubleValue !== undefined && valObj.doubleValue !== null) {
          values.push(valObj.doubleValue);
        } else if (valObj.integerValue !== undefined && valObj.integerValue !== null) {
          values.push(Number(valObj.integerValue));
        }
      }
    });

    if (values.length === 0) return null;

    // Sort values for median and min/max
    values.sort((a, b) => a - b);

    const min = values[0];
    const max = values[values.length - 1];
    
    // Average
    const sum = values.reduce((acc, v) => acc + v, 0);
    const avg = sum / values.length;

    // Median
    let median = 0;
    const mid = Math.floor(values.length / 2);
    if (values.length % 2 === 0) {
      median = (values[mid - 1] + values[mid]) / 2;
    } else {
      median = values[mid];
    }

    // Build Bins for Chart.js Histogram
    const binCount = Math.min(5, values.length);
    const labels: string[] = [];
    const counts: number[] = [];
    
    if (min === max) {
      labels.push(`${min}`);
      counts.push(values.length);
    } else {
      const binWidth = (max - min) / binCount;
      for (let i = 0; i < binCount; i++) {
        const binMin = min + i * binWidth;
        const binMax = binMin + binWidth;
        const count = values.filter(v => {
          if (i === binCount - 1) {
            return v >= binMin && v <= binMax;
          }
          return v >= binMin && v < binMax;
        }).length;

        labels.push(`${binMin.toFixed(1)} - ${binMax.toFixed(1)}`);
        counts.push(count);
      }
    }

    const chartData = {
      labels,
      datasets: [
        {
          label: 'Response Count',
          data: counts,
          backgroundColor: 'rgba(99, 102, 241, 0.75)', // indigo accent
          borderColor: '#6366f1',
          borderWidth: 1,
          hoverBackgroundColor: '#6366f1',
        }
      ]
    };

    return {
      count: values.length,
      min,
      max,
      avg,
      median,
      chartData
    };
  };

  const getChoiceStats = (field: any) => {
    if (!results || !results.submissions || !field.selectOptions?.options) return null;

    const options = field.selectOptions.options;
    const counts: Record<string, number> = {};
    
    options.forEach((opt: any) => {
      counts[opt.value] = 0;
    });

    let totalResponses = 0;

    results.submissions.forEach(sub => {
      const valObj = sub.values.find(v => v.fieldId === field.id);
      if (!valObj) return;

      if (field.type === FieldType.MULTI_SELECT) {
        const bitmaskVal = valObj.bitmaskValue || 0;
        let responded = false;
        options.forEach((opt: any) => {
          if ((bitmaskVal & (1 << opt.bit)) !== 0) {
            counts[opt.value]++;
            responded = true;
          }
        });
        if (responded) totalResponses++;
      } else if (field.type === FieldType.RADIO || field.type === FieldType.SELECT) {
        const textVal = valObj.stringValue;
        if (textVal && counts[textVal] !== undefined) {
          counts[textVal]++;
          totalResponses++;
        }
      }
    });

    if (totalResponses === 0) return null;

    const labels = options.map((opt: any) => opt.label);
    const data = options.map((opt: any) => counts[opt.value]);

    const chartData = {
      labels,
      datasets: [
        {
          label: 'Response Count',
          data,
          backgroundColor: 'rgba(99, 102, 241, 0.75)',
          borderColor: '#6366f1',
          borderWidth: 1,
          hoverBackgroundColor: '#6366f1',
        }
      ]
    };

    return {
      count: totalResponses,
      chartData
    };
  };

  const getCheckboxStats = (field: any) => {
    if (!results || !results.submissions) return null;

    let checkedCount = 0;
    let uncheckedCount = 0;
    let totalResponses = 0;

    results.submissions.forEach(sub => {
      const valObj = sub.values.find(v => v.fieldId === field.id);
      if (!valObj) return;

      if (valObj.boolValue) {
        checkedCount++;
      } else {
        uncheckedCount++;
      }
      totalResponses++;
    });

    if (totalResponses === 0) return null;

    const chartData = {
      labels: ['Checked (Yes)', 'Unchecked (No)'],
      datasets: [
        {
          label: 'Response Count',
          data: [checkedCount, uncheckedCount],
          backgroundColor: 'rgba(99, 102, 241, 0.75)',
          borderColor: '#6366f1',
          borderWidth: 1,
          hoverBackgroundColor: '#6366f1',
        }
      ]
    };

    return {
      count: totalResponses,
      chartData
    };
  };

  const isAnalyzable = (field: any) => {
    return (
      field.type === FieldType.NUMBER ||
      field.type === FieldType.RADIO ||
      field.type === FieldType.SELECT ||
      field.type === FieldType.MULTI_SELECT ||
      field.type === FieldType.CHECKBOX
    );
  };

  const renderFormStyleValue = (field: any, valObj: any) => {
    const textVal = valObj?.stringValue || '';
    const numVal = valObj?.doubleValue !== undefined ? valObj.doubleValue : (valObj?.integerValue !== undefined ? Number(valObj.integerValue) : null);
    const boolVal = valObj?.boolValue || false;
    const bitmaskVal = valObj?.bitmaskValue || 0;

    const disabledInputStyle = {
      width: '100%',
      padding: '0.75rem 1rem',
      borderRadius: '6px',
      border: '1px solid var(--border)',
      background: 'var(--input-bg, rgba(255,255,255,0.01))',
      color: 'var(--text)',
      opacity: 0.8,
      cursor: 'not-allowed',
      fontSize: '1rem',
      fontWeight: 500
    };

    if (field.type === FieldType.TEXTAREA) {
      return (
        <textarea
          value={textVal}
          disabled
          rows={3}
          style={{ ...disabledInputStyle, resize: 'none' }}
        />
      );
    }

    if (field.type === FieldType.NUMBER) {
      return (
        <input
          type="number"
          value={numVal !== null ? numVal : ''}
          disabled
          style={disabledInputStyle}
        />
      );
    }

    if (field.type === FieldType.CHECKBOX) {
      return (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.25rem 0' }}>
          <input
            type="checkbox"
            checked={boolVal}
            disabled
            style={{ width: '1.25rem', height: '1.25rem', cursor: 'not-allowed' }}
          />
          <span style={{ fontSize: '1rem', color: 'var(--text)' }}>
            I acknowledge and confirm this data point.
          </span>
        </div>
      );
    }

    if (field.type === FieldType.RADIO) {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', padding: '0.25rem 0' }}>
          {field.selectOptions?.options.map((opt: any) => {
            const isChecked = textVal === opt.value;
            return (
              <div key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <input
                  type="radio"
                  checked={isChecked}
                  disabled
                  style={{ width: '1.25rem', height: '1.25rem', cursor: 'not-allowed' }}
                />
                <span style={{ 
                  fontSize: '1rem', 
                  color: isChecked ? 'var(--text)' : 'var(--text-muted)',
                  fontWeight: isChecked ? 600 : 400 
                }}>
                  {opt.label}
                </span>
              </div>
            );
          })}
        </div>
      );
    }

    if (field.type === FieldType.SELECT) {
      return (
        <select
          value={textVal}
          disabled
          style={{ ...disabledInputStyle, appearance: 'none', WebkitAppearance: 'none' }}
        >
          <option value="">{field.placeholder || "Select an option..."}</option>
          {field.selectOptions?.options.map((opt: any) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      );
    }

    if (field.type === FieldType.MULTI_SELECT) {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', padding: '0.25rem 0' }}>
          {field.selectOptions?.options.map((opt: any) => {
            const isChecked = (bitmaskVal & (1 << opt.bit)) !== 0;
            return (
              <div key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <input
                  type="checkbox"
                  checked={isChecked}
                  disabled
                  style={{ width: '1.25rem', height: '1.25rem', cursor: 'not-allowed' }}
                />
                <span style={{ 
                  fontSize: '1rem', 
                  color: isChecked ? 'var(--text)' : 'var(--text-muted)',
                  fontWeight: isChecked ? 600 : 400 
                }}>
                  {opt.label}
                </span>
              </div>
            );
          })}
        </div>
      );
    }

    const inputType = 
      field.type === FieldType.EMAIL ? 'email' : 
      field.type === FieldType.URL ? 'url' : 
      field.type === FieldType.DATE ? 'date' : 
      field.type === FieldType.TIME ? 'time' : 'text';

    return (
      <input
        type={inputType}
        value={textVal}
        disabled
        style={disabledInputStyle}
      />
    );
  };

  const getChartOptions = (isDarkTheme: boolean) => ({
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: isDarkTheme ? '#1f2937' : '#ffffff',
        titleColor: isDarkTheme ? '#f9fafb' : '#0f172a',
        bodyColor: isDarkTheme ? '#f3f4f6' : '#334155',
        borderColor: isDarkTheme ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
        borderWidth: 1,
      }
    },
    scales: {
      x: {
        grid: { color: isDarkTheme ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)' },
        ticks: { color: isDarkTheme ? '#94a3b8' : '#475569' }
      },
      y: {
        grid: { color: isDarkTheme ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)' },
        ticks: { color: isDarkTheme ? '#94a3b8' : '#475569', stepSize: 1 }
      }
    }
  });

  const totalPages = Math.ceil((Number(results?.totalSubmissions) || 0) / limit);

  const handlePageChange = (newPage: number) => {
    setSearchParams({ page: newPage.toString() });
  };

  const handleExportJSON = async () => {
    if (!isAuthenticated || !form) return;
    setExporting(true);
    try {
      const headers = await getAuthHeaders();
      const res = await fetch(`${API_URL}/forms/${id}/results?limit=1000000&offset=0`, { headers });
      if (!res.ok) throw new Error("Failed to fetch data for export.");

      const resultsBuffer = await res.arrayBuffer();
      const decodedResults = decodeFormResults(new Uint8Array(resultsBuffer));

      const exportData = {
        form: {
          id: form.id,
          name: form.name,
          description: form.description,
          owner: form.owner,
          createdAt: new Date(Number(form.createdAt)).toLocaleString(),
        },
        submissions: decodedResults.submissions.map(sub => {
          const mappedSub: Record<string, string> = {
            "Submitted At": new Date(Number(sub.submittedAt)).toLocaleString()
          };
          form.fields.forEach(field => {
            const val = sub.values.find(v => v.fieldId === field.id);
            mappedSub[field.label] = formatValue(val, field);
          });
          return mappedSub;
        })
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${form.name.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase()}_results.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("Failed to export: " + (err as Error).message);
    } finally {
      setExporting(false);
    }
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
      <Link to="/dashboard" className="primary-button">Return to Dashboard</Link>
    </div>
  );

  return (
    <div className="form-results animate-fade-in" style={{ paddingBottom: '10rem' }}>
      <div className="results-header" style={{ marginBottom: '4rem' }}>
        <Link to="/dashboard" className="text-button" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '2rem', padding: 0 }}>
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
          <div>
            <h1 style={{ fontSize: 'clamp(2.5rem, 10vw, 4rem)', fontWeight: 900, marginBottom: '1rem', letterSpacing: '-0.04em', overflowWrap: 'anywhere' }}>{form?.name}</h1>
            <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center' }}>
              {((form != null && form!.deadline > 0)) && (
                <span className="badge" style={{ background: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.2)', color: 'var(--error)', fontSize: '0.875rem' }}>
                  Deadline: {new Date(Number(form!.deadline) * 1000).toLocaleString()}
                </span>
              )}
            </div>
          </div>
          <button
            className="secondary-button"
            onClick={handleExportJSON}
            disabled={exporting}
            style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}
          >
            {exporting ? <Loader2 size={18} style={{ animation: 'spin 2s linear infinite' }} /> : <Download size={18} />}
            {exporting ? 'Exporting...' : 'Export JSON'}
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '2.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.2rem' }}>
        <button
          onClick={() => setActiveTab('table')}
          style={{
            fontWeight: 700,
            fontSize: '1rem',
            padding: '0.5rem 1.5rem',
            border: 'none',
            borderBottom: activeTab === 'table' ? '2px solid var(--accent)' : '2px solid transparent',
            color: activeTab === 'table' ? 'var(--text)' : 'var(--text-muted)',
            borderRadius: 0,
            background: 'none',
            cursor: 'pointer'
          }}
        >
          Submissions Table
        </button>
        <button
          onClick={() => setActiveTab('analytics')}
          style={{
            fontWeight: 700,
            fontSize: '1rem',
            padding: '0.5rem 1.5rem',
            border: 'none',
            borderBottom: activeTab === 'analytics' ? '2px solid var(--accent)' : '2px solid transparent',
            color: activeTab === 'analytics' ? 'var(--text)' : 'var(--text-muted)',
            borderRadius: 0,
            background: 'none',
            cursor: 'pointer'
          }}
        >
          Analytics & Charts
        </button>
      </div>

      {activeTab === 'table' && (
        <>
          <div className="results-content card" style={{ padding: 0, overflowX: 'auto', border: '1px solid var(--border)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border)' }}>
                  <th style={{ padding: '1.5rem 2rem', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>Timestamp</th>
                  {form?.fields.map(field => (
                    <th key={field.id} style={{ padding: '1.5rem 2rem', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>
                      {field.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {results?.submissions.map((submission, idx) => (
                  <tr 
                    key={idx} 
                    onClick={() => setSelectedSubmission(submission)}
                    style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.2s', cursor: 'pointer' }} 
                    className="result-row"
                  >
                    <td style={{ padding: '1.5rem 2rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                      {new Date(Number(submission.submittedAt)).toLocaleString()}
                    </td>
                    {form?.fields.map(field => {
                      const fieldValue = submission.values.find(v => v.fieldId === field.id);
                      return (
                        <td key={field.id} style={{ padding: '1.5rem 2rem', fontSize: '1rem', fontWeight: 500 }}>
                          {formatValue(fieldValue, field)}
                        </td>
                      );
                    })}
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

          {results?.submitterEmails && results.submitterEmails.length > 0 && userTier === 'team' && (
            <div className="card" style={{ marginTop: '2.5rem', padding: '2rem' }}>
              <h3 style={{ marginTop: 0, fontSize: '1.25rem', marginBottom: '1rem' }}>
                Verified Respondents ({results.submitterEmails.length})
              </h3>
              <p className="text-muted" style={{ fontSize: '0.9rem', marginBottom: '1.5rem' }}>
                The following individuals have verified their access and submitted responses (responses are cryptographically decoupled from these identities):
              </p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {results.submitterEmails.map((email: string, idx: number) => (
                  <span key={idx} className="badge" style={{ background: 'rgba(59, 130, 246, 0.1)', borderColor: 'rgba(59, 130, 246, 0.2)', fontSize: '0.9rem', padding: '0.4rem 0.8rem' }}>
                    {email}
                  </span>
                ))}
              </div>
            </div>
          )}

          {results?.form?.participantMode !== 2 && userTier !== 'team' && (
            <div className="card" style={{ marginTop: '2.5rem', padding: '2rem', border: '1px dashed var(--border)', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
              <Lock size={36} style={{ color: 'var(--accent)', marginBottom: '1rem' }} />
              <h3 style={{ marginTop: 0, fontSize: '1.25rem', marginBottom: '0.5rem' }}>
                Reveal Verified Respondents
              </h3>
              <p className="text-muted" style={{ fontSize: '0.9rem', maxWidth: '500px', marginBottom: '1.5rem' }}>
                Identity-separation keeps submissions mathematically anonymous. However, Team tier owners can view the list of authenticated email participants who submitted the form.
              </p>
              <Link to="/subscription" className="secondary-button" style={{ padding: '0.6rem 1.2rem', fontSize: '0.875rem' }}>
                🔒 Upgrade to Team Plan
              </Link>
            </div>
          )}

          {totalPages > 1 && (
            <div className="pagination" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '2rem', marginTop: '4rem' }}>
              <button
                className="secondary-button"
                disabled={page === 1}
                onClick={() => handlePageChange(page - 1)}
                style={{ padding: '0.75rem 1.5rem' }}
              >
                <ChevronLeft size={18} /> Previous
              </button>
              <span style={{ fontWeight: 700, color: 'var(--text)' }}>
                Page <span style={{ color: 'var(--accent)' }}>{page}</span> of {totalPages}
              </span>
              <button
                className="secondary-button"
                disabled={page === totalPages}
                onClick={() => handlePageChange(page + 1)}
                style={{ padding: '0.75rem 1.5rem' }}
              >
                Next <ChevronRight size={18} />
              </button>
            </div>
          )}
        </>
      )}

      {activeTab === 'analytics' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2.5rem' }}>
          {form?.fields.filter(isAnalyzable).length === 0 ? (
            <div style={{ padding: '6rem', textAlign: 'center', color: 'var(--text-muted)', background: 'rgba(255,255,255,0.01)', border: '1px dashed var(--border)', borderRadius: '8px' }}>
              <BarChart3 size={64} style={{ margin: '0 auto 1.5rem', opacity: 0.2 }} />
              No analyzable fields (numeric, radio, select, multi-select, or checkbox) found in this form.
            </div>
          ) : (
            form?.fields.filter(isAnalyzable).map(field => {
              if (field.type === FieldType.NUMBER) {
                const stats = getNumericalStats(field.id);
                if (!stats) return null;

                return (
                  <div key={field.id} className="card" style={{ padding: '2.5rem' }}>
                    <h3 style={{ marginTop: 0, fontSize: '1.35rem', marginBottom: '2rem', borderBottom: '1px solid var(--border)', paddingBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text)' }}>
                      <span>{field.label}</span>
                      <span style={{ fontSize: '0.875rem', fontWeight: 400, color: 'var(--text-muted)' }}>{stats.count} responses</span>
                    </h3>

                    {/* Metrics grid */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '1.5rem', marginBottom: '3rem' }}>
                      <div style={{ padding: '1.25rem', background: 'var(--input-bg, rgba(0,0,0,0.02))', borderRadius: '8px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem' }}>Average (Mean)</div>
                        <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--accent)' }}>{stats.avg.toFixed(2)}</div>
                      </div>
                      <div style={{ padding: '1.25rem', background: 'var(--input-bg, rgba(0,0,0,0.02))', borderRadius: '8px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem' }}>Median</div>
                        <div style={{ fontSize: '1.75rem', fontWeight: 'bold' }}>{stats.median.toFixed(1)}</div>
                      </div>
                      <div style={{ padding: '1.25rem', background: 'var(--input-bg, rgba(0,0,0,0.02))', borderRadius: '8px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem' }}>Min Value</div>
                        <div style={{ fontSize: '1.75rem', fontWeight: 'bold' }}>{stats.min.toFixed(1)}</div>
                      </div>
                      <div style={{ padding: '1.25rem', background: 'var(--input-bg, rgba(0,0,0,0.02))', borderRadius: '8px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem' }}>Max Value</div>
                        <div style={{ fontSize: '1.75rem', fontWeight: 'bold' }}>{stats.max.toFixed(1)}</div>
                      </div>
                    </div>

                    {/* Histogram Chart using Chart.js Bar */}
                    <div style={{ height: '300px', width: '100%', position: 'relative' }}>
                      <h4 style={{ fontSize: '0.875rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '1.5rem' }}>Value Distribution (Histogram)</h4>
                      <div style={{ height: '240px', width: '100%' }}>
                        <Bar 
                          data={stats.chartData} 
                          options={getChartOptions(isDark)}
                        />
                      </div>
                    </div>
                  </div>
                );
              }

              // Otherwise it's a multi-choice field (radio, select, multi-select) or checkbox
              const stats = field.type === FieldType.CHECKBOX ? getCheckboxStats(field) : getChoiceStats(field);
              if (!stats) return null;

              return (
                <div key={field.id} className="card" style={{ padding: '2.5rem' }}>
                  <h3 style={{ marginTop: 0, fontSize: '1.35rem', marginBottom: '2rem', borderBottom: '1px solid var(--border)', paddingBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text)' }}>
                    <span>{field.label}</span>
                    <span style={{ fontSize: '0.875rem', fontWeight: 400, color: 'var(--text-muted)' }}>{stats.count} responses</span>
                  </h3>

                  <div style={{ height: '300px', width: '100%', position: 'relative' }}>
                    <h4 style={{ fontSize: '0.875rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '1.5rem' }}>Option Pick Rates</h4>
                    <div style={{ height: '240px', width: '100%' }}>
                      <Bar 
                        data={stats.chartData} 
                        options={getChartOptions(isDark)}
                      />
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Submission Detail Modal */}
      {selectedSubmission && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.4)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000,
          backdropFilter: 'blur(10px)',
          padding: '1rem'
        }} onClick={() => setSelectedSubmission(null)}>
          <div style={{
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: '12px',
            width: '100%',
            maxWidth: '650px',
            maxHeight: '90vh',
            overflowY: 'auto',
            padding: '2.5rem',
            position: 'relative',
            boxShadow: '0 20px 25px -5px var(--shadow)'
          }} onClick={e => e.stopPropagation()}>
            <button 
              onClick={() => setSelectedSubmission(null)}
              style={{
                position: 'absolute',
                top: '1.5rem',
                right: '1.5rem',
                background: 'none',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '1.5rem',
                padding: 0
              }}
            >
              &times;
            </button>
            <h2 style={{ marginTop: 0, marginBottom: '2.5rem', fontSize: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '1.25rem', color: 'var(--text)' }}>
              Submission Detail
              <span style={{ display: 'block', fontSize: '0.875rem', fontWeight: 400, color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                Submitted on {new Date(Number(selectedSubmission.submittedAt)).toLocaleString()}
              </span>
            </h2>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              {form?.fields.map((field, index) => {
                const valObj = selectedSubmission.values.find((v: any) => v.fieldId === field.id);
                return (
                  <div key={field.id} style={{ borderBottom: '1px solid var(--border)', paddingBottom: '2rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      <span>{field.label}</span>
                      <span>0{index + 1}</span>
                    </div>
                    <div>
                      {renderFormStyleValue(field, valObj)}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      <style>{`
        .result-row:hover { background: rgba(255,255,255,0.02); }
        th { white-space: nowrap; }
        .secondary-button:disabled { opacity: 0.3; cursor: not-allowed; }
      `}</style>
    </div>
  );
};
