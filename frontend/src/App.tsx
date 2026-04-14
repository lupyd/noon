import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useNavigate } from 'react-router-dom';

import { useAuth0 } from '@auth0/auth0-react';
import { FormBuilder } from './components/FormBuilder';
import { FormSubmission } from './components/FormSubmission';
import { LogIn, LogOut } from 'lucide-react';
import { SunLogo } from './components/logo';
import './App.css';

function Home() {
  const [targetId, setTargetId] = useState('');
  const navigate = useNavigate();

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
        <div className="noon-logo noon-logo-hero">
          <span>N</span>
          <SunLogo height={160} />
          <span>N</span>
        </div>
        <h1>DECENTRALIZED<br/>SECURE FORMS</h1>
        <p>The next generation of private data collection. Beautiful, anonymous, and cryptographically secure.</p>
        
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
          </div>
        </div>
      </div>
    </div>
  );
}

function App() {
  const { isAuthenticated, loginWithRedirect, logout, user, isLoading } = useAuth0();

  return (
    <Router>
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
            <nav className="navbar-nav">
              <Link to="/create">Build</Link>
              <a href="http://localhost:39210/health" target="_blank" rel="noreferrer">Status</a>
              
              <div className="auth-section">
                {isLoading ? (
                  <span className="text-muted">Loading...</span>
                ) : isAuthenticated ? (
                  <>
                    <span className="user-greeting">Hi, {user?.given_name || user?.name?.split('@')[0]}</span>
                    <button 
                      onClick={() => logout({ logoutParams: { returnTo: window.location.origin } })} 
                      className="icon-button" 
                      title="Log Out"
                    >
                      <LogOut size={18} />
                    </button>
                  </>
                ) : (
                  <button 
                    onClick={() => loginWithRedirect()} 
                    className="primary-button nav-button"
                  >
                    <LogIn size={16} /> Log In
                  </button>
                )}
              </div>
            </nav>
          </div>
        </header>

        <main className="container main-content">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/index.html" element={<Navigate to="/" replace />} />
            <Route path="/create" element={<FormBuilder />} />
            <Route path="/forms/:id" element={<FormSubmission />} />
          </Routes>

        </main>

        <footer className="footer">
          <div className="container">
            <p>&copy; 2026 Lupyd Foundation. All rights reserved.</p>
          </div>
        </footer>
      </div>
    </Router>
  );
}

export default App;
