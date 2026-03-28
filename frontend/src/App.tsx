import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { useAuth0 } from '@auth0/auth0-react';
import { FormBuilder } from './components/FormBuilder';
import { FormSubmission } from './components/FormSubmission';
import { LogIn, LogOut } from 'lucide-react';
import './App.css';

function Home() {
  return (
    <div className="home card animate-fade-in">
      <div className="hero">
        <img src="/noon.webp" alt="Noon Forms" className="hero-logo" />
        <h1>Welcome to Noon Forms</h1>
        <p>Create beautiful, secure, and anonymous forms in seconds.</p>
        <div className="home-actions">
          <Link to="/create" className="primary-button large">Create New Form</Link>
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
            <Link to="/" className="logo"><img src="/noon.webp" alt="Noon Forms" /></Link>
            <nav style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
              <Link to="/create" style={{ marginLeft: 0 }}>Build</Link>
              <a href="http://localhost:39210/health" target="_blank" rel="noreferrer" style={{ marginLeft: 0 }}>Status</a>
              
              <div className="auth-section" style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginLeft: '1rem', borderLeft: '1px solid var(--border)', paddingLeft: '1.5rem' }}>
                {isLoading ? (
                  <span style={{ color: 'var(--text-muted)' }}>Loading...</span>
                ) : isAuthenticated ? (
                  <>
                    <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>Hi, {user?.given_name || user?.name?.split('@')[0]}</span>
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
                    className="primary-button" 
                    style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}
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
