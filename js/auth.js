/**
 * OSA — Authentication Module
 * Handles login, logout, session, role-based access
 */

const OSA_AUTH = (() => {
  const SESSION_KEY = 'osa_session';
  const USER_PREFS_KEY = 'osa_user_prefs';

  let _currentUser = null;
  let _currentProfile = null;

  // --- Session ---

  function saveSessionLocal(session) {
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify({
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_at: session.expires_at
      }));
    } catch (e) {
      console.warn('[OSA] Não foi possível guardar sessão local:', e);
    }
  }

  function clearSessionLocal() {
    try {
      localStorage.removeItem(SESSION_KEY);
    } catch (e) { /* ignore */ }
  }

  // --- Login ---

  async function login(email, password) {
    const sb = getSupabase();
    if (!sb) return { ok: false, error: 'Supabase não configurado' };

    const { data, error } = await sb.auth.signInWithPassword({ email, password });

    if (error) {
      return { ok: false, error: error.message, status: error.status };
    }

    if (!data.session) {
      return { ok: false, error: 'Sessão não retornada pelo Supabase' };
    }

    saveSessionLocal(data.session);
    _currentUser = data.user;

    // Load profile
    const profileResult = await loadProfile(data.user.id);
    if (!profileResult.ok) {
      return { ok: false, error: 'Perfil não encontrado: ' + profileResult.error };
    }

    _currentProfile = profileResult.data;

    return { ok: true, user: data.user, profile: _currentProfile };
  }

  // --- Logout ---

  async function logout() {
    const sb = getSupabase();
    if (sb) {
      await sb.auth.signOut();
    }
    _currentUser = null;
    _currentProfile = null;
    clearSessionLocal();
  }

  // --- Session restore ---

  async function restoreSession() {
    const sb = getSupabase();
    if (!sb) return { ok: false, error: 'Supabase não configurado' };

    const { data, error } = await sb.auth.getSession();

    if (error || !data.session) {
      clearSessionLocal();
      return { ok: false, error: error?.message || 'Sem sessão ativa' };
    }

    _currentUser = data.session.user;
    saveSessionLocal(data.session);

    const profileResult = await loadProfile(_currentUser.id);
    if (!profileResult.ok) {
      return { ok: false, error: 'Perfil não encontrado' };
    }

    _currentProfile = profileResult.data;
    return { ok: true, user: _currentUser, profile: _currentProfile };
  }

  // --- Profile ---

  async function loadProfile(userId) {
    return OSA_DATA.read('profiles', {
      filter: { column: 'id', value: userId },
      single: true
    });
  }

  // --- Current user getters ---

  function getCurrentUser() {
    return _currentUser;
  }

  function getCurrentProfile() {
    return _currentProfile;
  }

  function getRole() {
    return _currentProfile?.role || null;
  }

  function getRoleLevel() {
    const role = getRole();
    return OSA_CONFIG.ROLES[role]?.level || 0;
  }

  function isAdmin() {
    return getRole() === 'admin';
  }

  function isJuniorAdmin() {
    return getRole() === 'junior_admin' || isAdmin();
  }

  function isCashier() {
    return getRole() === 'cashier';
  }

  function canSeeCosts() {
    return isJuniorAdmin();
  }

  function canSeeProfits() {
    return isJuniorAdmin();
  }

  function canDelete() {
    return isAdmin();
  }

  function canManageUsers() {
    return isAdmin();
  }

  function canManageCategories() {
    return isAdmin();
  }

  function canManageConfigs() {
    return isAdmin();
  }

  function canManageTransfers() {
    return isJuniorAdmin();
  }

  function canManageInventory() {
    return isJuniorAdmin();
  }

  function canManageLosses() {
    return isJuniorAdmin();
  }

  function canManageThefts() {
    return isJuniorAdmin();
  }

  function canManageFuel() {
    return isJuniorAdmin();
  }

  function canViewReports() {
    return isJuniorAdmin();
  }

  function canViewAudit() {
    return isAdmin();
  }

  function canManageClosings() {
    return isAdmin();
  }

  // --- User preferences (localStorage only for UI preferences) ---

  function getUserPrefs() {
    try {
      return JSON.parse(localStorage.getItem(USER_PREFS_KEY)) || {};
    } catch (e) {
      return {};
    }
  }

  function setUserPrefs(prefs) {
    try {
      localStorage.setItem(USER_PREFS_KEY, JSON.stringify(prefs));
    } catch (e) { /* ignore */ }
  }

  // --- Password reset ---

  async function resetPassword(email) {
    const sb = getSupabase();
    if (!sb) return { ok: false, error: 'Supabase não configurado' };

    const { error } = await sb.auth.resetPasswordForEmail(email, {
      redirectTo: window.location.origin + '/login.html'
    });

    if (error) return { ok: false, error: error.message };
    return { ok: true };
  }

  // --- Register user (admin only via Supabase admin) ---

  async function registerUser(email, password, fullName, role) {
    const sb = getSupabase();
    if (!sb) return { ok: false, error: 'Supabase não configurado' };

    // Use admin auth to create user — requires service role key or admin dashboard
    // For now, use signUp with metadata
    const { data, error } = await sb.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName,
          role: role
        }
      }
    });

    if (error) return { ok: false, error: error.message, status: error.status };
    if (!data.user) return { ok: false, error: 'Utilizador não criado pelo Supabase' };

    return { ok: true, user: data.user };
  }

  // --- Update profile ---

  async function updateProfile(userId, updates) {
    return OSA_DATA.update('profiles', userId, updates);
  }

  return {
    login,
    logout,
    restoreSession,
    getCurrentUser,
    getCurrentProfile,
    getRole,
    getRoleLevel,
    isAdmin,
    isJuniorAdmin,
    isCashier,
    canSeeCosts,
    canSeeProfits,
    canDelete,
    canManageUsers,
    canManageCategories,
    canManageConfigs,
    canManageTransfers,
    canManageInventory,
    canManageLosses,
    canManageThefts,
    canManageFuel,
    canViewReports,
    canViewAudit,
    canManageClosings,
    getUserPrefs,
    setUserPrefs,
    resetPassword,
    registerUser,
    updateProfile,
    loadProfile
  };
})();
