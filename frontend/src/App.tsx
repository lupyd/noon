import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useNavigate } from 'react-router-dom';
import { FormBuilder } from './components/FormBuilder';
import { FormSubmission } from './components/FormSubmission';
import { FormResults } from './components/FormResults';
import { Dashboard } from './components/Dashboard';
import { LogOut } from 'lucide-react';
import { SunLogo } from './components/logo';
import { UnifiedAuthProvider, useUnifiedAuth } from './auth';
import { ThemeProvider } from './ThemeContext';
import { ThemeToggle } from './components/ThemeToggle';
import './App.css';

function Home() {
  const [targetId, setTargetId] = useState('');
  const navigate = useNavigate();
  const { isAuthenticated } = useUnifiedAuth();

  const handleJoin = (e: React.FormEvent) => {
    e.preventDefault();
    if (targetId.trim()) {
      let id = targetId.trim();
      // Handle full URLs if pasted
      if (id.includes('/forms/')) {
        id = id.split('/forms/').pop()?.split('?')[0] || '';
      }
      if (id) {
        navigate(`/forms/${id}`);
      }
    }
  };

  return (
    <div className="home animate-fade-in">
      <div className="hero">
        <div className="noon-logo noon-logo-hero" style={{ marginBottom: '2rem' }}>
          <span>N</span>
          <SunLogo height={160} />
          <span>N</span>
        </div>
        <h1>TRULY ANONYMOUS<br />SURVEYS</h1>

        <div className="home-search-container">
          <form onSubmit={handleJoin} className="search-form">
            <input
              type="text"
              placeholder="Paste form URL or ID here..."
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              className="search-input"
            />
            <button type="submit" className="primary-button join-button">
              Fill Form
            </button>
          </form>

          <div className="search-divider">
            <span>OR</span>
          </div>

          <div className="home-actions">
            <Link to="/create" className="secondary-button large">
              Create New Form
            </Link>
            {isAuthenticated && (
              <Link to="/dashboard" className="text-button" style={{ marginTop: '1rem', display: 'block' }}>
                Go to Dashboard
              </Link>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function NavBarContent() {
  const { isAuthenticated, isInitialLoading, email, logout } = useUnifiedAuth();

  return (
    <nav className="navbar-nav">
      <Link to="/dashboard">Dashboard</Link>
      <a href="https://github.com/lupyd/noon.git" target="_blank" rel="noopener noreferrer" style={{ display: 'flex', alignItems: 'center' }} title="View on GitHub">
        <svg height="20" viewBox="0 0 16 16" width="20" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg>
      </a>
      <ThemeToggle />

      <div className="auth-section" style={{ borderLeft: isAuthenticated ? '1px solid var(--border)' : 'none' }}>
        {isInitialLoading ? (
          <span className="text-muted">Loading...</span>
        ) : isAuthenticated && (
          <>
            <span className="user-greeting" style={{ maxWidth: '150px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              Hi, {email?.split('@')[0]}
            </span>
            <button
              onClick={() => logout()}
              className="icon-button"
              title="Log Out"
            >
              <LogOut size={18} />
            </button>
          </>
        )}
      </div>
    </nav>
  );
}

function App() {
  return (
    <Router>
      <ThemeProvider>
        <UnifiedAuthProvider>
          <div className="App">
            <header className="navbar">
              <div className="container">
                <Link to="/" className="logo">
                  <div className="noon-logo">
                    <span>N</span>
                    <SunLogo height={40} />
                    <span>N</span>
                  </div>
                </Link>
                <NavBarContent />
              </div>
            </header>

            <main className="container main-content">
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/index.html" element={<Navigate to="/" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/create" element={<FormBuilder />} />
                <Route path="/forms/:id" element={<FormSubmission />} />
                <Route path="/forms/:id/results" element={<FormResults />} />
              </Routes>

            </main>

            <footer className="footer">
              <div className="container">
                <p>&copy; 2026 Lupyd Foundation. All rights reserved.</p>
              </div>
            </footer>
          </div>
        </UnifiedAuthProvider>
      </ThemeProvider>
    </Router>
  );
}

export default App;
