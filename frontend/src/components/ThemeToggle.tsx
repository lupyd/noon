import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../ThemeContext';

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      className="theme-toggle-btn"
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
    >
      <div className="theme-toggle-content">
        <div className={`theme-toggle-icon ${theme === 'dark' ? 'icon-visible' : 'icon-hidden-below'}`}>
          <Sun size={20} />
        </div>
        <div className={`theme-toggle-icon ${theme === 'light' ? 'icon-visible' : 'icon-hidden-above'}`}>
          <Moon size={20} />
        </div>
      </div>
    </button>
  );
}
