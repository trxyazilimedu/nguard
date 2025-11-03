/**
 * Example React Components for Session Updates
 * Shows how to use updateSession() hook in different scenarios
 */

'use client';

import { useState } from 'react';
import { useAuth, useSession, useSessionUpdate } from 'nguard/client';

// ============================================================================
// Example 1: Simple Theme Switcher using useSessionUpdate
// ============================================================================

export function ThemeSwitcher() {
  const { user } = useAuth();
  const { updateSession, isLoading } = useSessionUpdate();

  const handleThemeChange = async (theme: 'light' | 'dark') => {
    if (!user) {
      alert('Please login first');
      return;
    }

    try {
      const response = await fetch('/api/auth/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ theme }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to update theme');
      }

      const data = await response.json();

      // Update session with new theme
      await updateSession(
        data.session.user,
        data.session.data
      );

      // Apply theme to DOM
      document.documentElement.setAttribute('data-theme', theme);
    } catch (error) {
      console.error('Theme update error:', error);
      alert(error instanceof Error ? error.message : 'Failed to update theme');
    }
  };

  return (
    <div className="theme-switcher">
      <button
        onClick={() => handleThemeChange('light')}
        disabled={isLoading}
        className="theme-btn"
      >
        {isLoading ? 'Updating...' : '☀️ Light'}
      </button>
      <button
        onClick={() => handleThemeChange('dark')}
        disabled={isLoading}
        className="theme-btn"
      >
        {isLoading ? 'Updating...' : '🌙 Dark'}
      </button>
    </div>
  );
}

// ============================================================================
// Example 2: Language Selector using useSession
// ============================================================================

export function LanguageSelector() {
  const { session, updateSession, isLoading } = useSession();
  const [selectedLanguage, setSelectedLanguage] = useState(
    session?.data?.language || 'en'
  );

  const handleLanguageChange = async (event: React.ChangeEvent<HTMLSelectElement>) => {
    const newLanguage = event.target.value as 'en' | 'tr';

    if (!session) {
      alert('Please login first');
      return;
    }

    try {
      const response = await fetch('/api/auth/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language: newLanguage }),
      });

      if (!response.ok) {
        throw new Error('Failed to update language');
      }

      const data = await response.json();

      // Update session
      await updateSession(data.session.user, data.session.data);

      // Update local state
      setSelectedLanguage(newLanguage);

      // Apply language to app
      document.documentElement.lang = newLanguage;
    } catch (error) {
      console.error('Language update error:', error);
      alert('Failed to update language');
      // Reset select to previous value on error
      setSelectedLanguage(session.data?.language || 'en');
    }
  };

  return (
    <div className="language-selector">
      <label htmlFor="lang-select">Select Language:</label>
      <select
        id="lang-select"
        value={selectedLanguage}
        onChange={handleLanguageChange}
        disabled={isLoading}
      >
        <option value="en">English</option>
        <option value="tr">Türkçe</option>
      </select>
    </div>
  );
}

// ============================================================================
// Example 3: Settings Panel with Multiple Options
// ============================================================================

interface Settings {
  theme: 'light' | 'dark';
  language: 'en' | 'tr';
  notifications: boolean;
  twoFactorEnabled: boolean;
}

export function SettingsPanel() {
  const { session, updateSession, isLoading, status } = useSession();
  const [settings, setSettings] = useState<Partial<Settings>>(
    (session?.data as any) || {}
  );
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [errors, setErrors] = useState<string[]>([]);

  if (status === 'loading') {
    return <div className="loading">Loading settings...</div>;
  }

  if (status === 'unauthenticated') {
    return <div className="error">Please login to access settings</div>;
  }

  const handleSettingChange = (key: keyof Settings, value: any) => {
    setSettings(prev => ({ ...prev, [key]: value }));
    setErrors([]); // Clear errors when user makes changes
  };

  const handleSaveSettings = async () => {
    if (!session) return;

    // Validate settings before sending
    const validationErrors: string[] = [];

    if (settings.theme && !['light', 'dark'].includes(settings.theme)) {
      validationErrors.push('Invalid theme selected');
    }

    if (settings.language && !['en', 'tr'].includes(settings.language)) {
      validationErrors.push('Invalid language selected');
    }

    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      return;
    }

    try {
      setSaveMessage(null);

      const response = await fetch('/api/auth/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to save settings');
      }

      const data = await response.json();

      // Update session
      await updateSession(data.session.user, data.session.data);

      setSaveMessage('✅ Settings saved successfully!');
      setErrors([]);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save settings';
      setErrors([errorMessage]);
    }
  };

  return (
    <div className="settings-panel">
      <h2>Settings</h2>

      {errors.length > 0 && (
        <div className="error-messages">
          {errors.map((err, i) => (
            <p key={i} className="error">❌ {err}</p>
          ))}
        </div>
      )}

      {saveMessage && (
        <div className="success-message">
          <p>{saveMessage}</p>
        </div>
      )}

      <div className="setting-group">
        <label htmlFor="theme">Theme:</label>
        <select
          id="theme"
          value={settings.theme || 'light'}
          onChange={(e) => handleSettingChange('theme', e.target.value)}
          disabled={isLoading}
        >
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </div>

      <div className="setting-group">
        <label htmlFor="language">Language:</label>
        <select
          id="language"
          value={settings.language || 'en'}
          onChange={(e) => handleSettingChange('language', e.target.value)}
          disabled={isLoading}
        >
          <option value="en">English</option>
          <option value="tr">Türkçe</option>
        </select>
      </div>

      <div className="setting-group">
        <label htmlFor="notifications">
          <input
            id="notifications"
            type="checkbox"
            checked={settings.notifications ?? true}
            onChange={(e) => handleSettingChange('notifications', e.target.checked)}
            disabled={isLoading}
          />
          Enable Notifications
        </label>
      </div>

      <div className="setting-group">
        <label htmlFor="2fa">
          <input
            id="2fa"
            type="checkbox"
            checked={settings.twoFactorEnabled ?? false}
            onChange={(e) => handleSettingChange('twoFactorEnabled', e.target.checked)}
            disabled={isLoading}
          />
          Enable Two-Factor Authentication
        </label>
      </div>

      <button
        onClick={handleSaveSettings}
        disabled={isLoading}
        className="save-btn"
      >
        {isLoading ? 'Saving...' : 'Save Settings'}
      </button>
    </div>
  );
}

// ============================================================================
// Example 4: Admin Panel - Change User Roles
// ============================================================================

interface User {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'moderator' | 'admin';
}

export function AdminPanel() {
  const { user: currentUser, isAuthenticated } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [usersLoaded, setUsersLoaded] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  if (!isAuthenticated) {
    return <div className="error">Please login first</div>;
  }

  const loadUsers = async () => {
    setLoading(true);
    setErrors([]);
    try {
      const response = await fetch('/api/users');
      if (!response.ok) throw new Error('Failed to load users');

      const data = await response.json();
      setUsers(data.users);
      setUsersLoaded(true);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to load users';
      setErrors([errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const changeUserRole = async (userId: string, newRole: string) => {
    setLoading(true);
    setErrors([]);

    try {
      const response = await fetch('/api/auth/update-role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newRole }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to change role');
      }

      const data = await response.json();

      // Update local state
      setUsers(users.map(u =>
        u.id === userId ? { ...u, role: newRole } : u
      ));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to change role';
      setErrors([errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="admin-panel">
      <h2>Admin Panel</h2>
      <p>Current User: <strong>{currentUser?.name}</strong> ({currentUser?.role})</p>

      {errors.length > 0 && (
        <div className="error-messages">
          {errors.map((err, i) => (
            <p key={i} className="error">❌ {err}</p>
          ))}
        </div>
      )}

      {!usersLoaded ? (
        <button onClick={loadUsers} disabled={loading}>
          {loading ? 'Loading...' : 'Load Users'}
        </button>
      ) : (
        <div className="users-table">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(user => (
                <tr key={user.id}>
                  <td>{user.name}</td>
                  <td>{user.email}</td>
                  <td>{user.role}</td>
                  <td>
                    <select
                      value={user.role}
                      onChange={(e) => changeUserRole(user.id, e.target.value)}
                      disabled={loading || user.id === currentUser?.id}
                      title={user.id === currentUser?.id ? 'Cannot change own role' : ''}
                    >
                      <option value="user">User</option>
                      <option value="moderator">Moderator</option>
                      <option value="admin">Admin</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Example 5: Profile Update Component
// ============================================================================

export function ProfileUpdate() {
  const { user, isAuthenticated } = useAuth();
  const { session, updateSession, isLoading } = useSession();
  const [formData, setFormData] = useState({
    name: user?.name || '',
    email: user?.email || '',
  });
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  if (!isAuthenticated || !user) {
    return <div>Please login first</div>;
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);

    if (!formData.name.trim()) {
      setMessage({ type: 'error', text: 'Name cannot be empty' });
      return;
    }

    try {
      const response = await fetch('/api/auth/profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        throw new Error('Failed to update profile');
      }

      const data = await response.json();

      // Update session with new profile data
      await updateSession(
        { ...user, ...formData },
        session?.data
      );

      setMessage({ type: 'success', text: '✅ Profile updated successfully!' });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to update profile';
      setMessage({ type: 'error', text: `❌ ${errorMessage}` });
    }
  };

  return (
    <div className="profile-update">
      <h2>Update Profile</h2>

      {message && (
        <div className={`message ${message.type}`}>
          {message.text}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="name">Name:</label>
          <input
            id="name"
            type="text"
            name="name"
            value={formData.name}
            onChange={handleChange}
            disabled={isLoading}
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="email">Email:</label>
          <input
            id="email"
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            disabled={isLoading}
            required
          />
        </div>

        <button type="submit" disabled={isLoading}>
          {isLoading ? 'Updating...' : 'Update Profile'}
        </button>
      </form>
    </div>
  );
}
