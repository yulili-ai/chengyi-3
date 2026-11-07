const API = (window.CHENGYI_API_BASE || '') + '/api/v1';
const TOKEN_KEY = 'chengyi3-account-token';
const GUEST_KEY = 'chengyi3-workbench-session';

export function accountToken() {
  try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}

async function api(path, body) {
  const token = accountToken();
  const res = await fetch(API + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const value = await res.json().catch(() => null);
  if (!res.ok || !value) throw Error(value?.error?.message || '请求没有完成');
  return value.data;
}

function guestMigration() {
  try {
    const guest = JSON.parse(sessionStorage.getItem(GUEST_KEY) || 'null');
    if (!guest?.id || !guest?.token) return [];
    return [{ project_id: guest.id, session_token: guest.token }];
  } catch { return []; }
}

export function initAuth(app) {
  const dialog = document.getElementById('auth-dialog');
  const button = document.getElementById('btn-account');
  const emailStep = document.getElementById('auth-email-step');
  const codeStep = document.getElementById('auth-code-step');
  const email = document.getElementById('auth-email');
  const code = document.getElementById('auth-code');
  const message = document.getElementById('auth-message');
  const projects = document.getElementById('auth-projects');
  const projectList = document.getElementById('auth-project-list');
  const logout = document.getElementById('auth-logout');
  let currentEmail = '';

  function showMessage(text) { message.textContent = text || ''; }
  function setLoggedOutUi() {
    button.textContent = '登录';
    emailStep.hidden = false;
    codeStep.hidden = true;
    projects.hidden = true;
    logout.hidden = true;
    document.getElementById('auth-title').textContent = '登录并保存作品';
  }
  async function refresh() {
    if (!accountToken()) { setLoggedOutUi(); return false; }
    try {
      const user = await api('/auth/me');
      button.textContent = user.email;
      document.getElementById('auth-title').textContent = '欢迎回来';
      emailStep.hidden = true;
      codeStep.hidden = true;
      logout.hidden = false;
      const items = await api('/pottery/projects');
      projectList.replaceChildren();
      projects.hidden = !items.length;
      for (const item of items) {
        const projectButton = document.createElement('button');
        projectButton.className = 'auth-project';
        projectButton.textContent = item.name || '未命名作品';
        projectButton.addEventListener('click', () => {
          try { sessionStorage.removeItem('chengyi3-workbench-session'); } catch {}
          try { sessionStorage.setItem('chengyi3-account-project', item.id); } catch {}
          dialog.close();
          app.go('workbench', { instant: true, force: true });
        });
        projectList.append(projectButton);
      }
      return true;
    } catch {
      try { localStorage.removeItem(TOKEN_KEY); } catch {}
      setLoggedOutUi();
      return false;
    }
  }

  button.addEventListener('click', () => {
    showMessage('');
    refresh().then(() => dialog.showModal());
  });
  document.getElementById('auth-send').addEventListener('click', async () => {
    currentEmail = email.value.trim();
    if (!currentEmail || !currentEmail.includes('@')) {
      showMessage('请输入有效邮箱');
      return;
    }
    try {
      const result = await api('/auth/email/request', { email: currentEmail });
      emailStep.hidden = true;
      codeStep.hidden = false;
      code.focus();
      showMessage(result.development_code
        ? '开发验证码：' + result.development_code
        : '验证码已发送，请查看邮箱');
    } catch (err) { showMessage(err.message); }
  });
  document.getElementById('auth-back').addEventListener('click', () => {
    emailStep.hidden = false;
    codeStep.hidden = true;
    showMessage('');
  });
  document.getElementById('auth-verify').addEventListener('click', async () => {
    if (!/^\d{6}$/.test(code.value)) {
      showMessage('请输入 6 位数字验证码');
      return;
    }
    try {
      const result = await api('/auth/email/verify', {
        email: currentEmail,
        code: code.value,
        guest_projects: guestMigration(),
      });
      try { localStorage.setItem(TOKEN_KEY, result.access_token); } catch {}
      showMessage('登录成功，正在恢复作品…');
      await refresh();
      dialog.close();
      app.go('workbench', { instant: true, force: true });
    } catch (err) { showMessage(err.message); }
  });
  logout.addEventListener('click', async () => {
    try { await api('/auth/logout', {}); } catch {}
    try { localStorage.removeItem(TOKEN_KEY); } catch {}
    setLoggedOutUi();
    app.go('workbench', { instant: true, force: true });
  });

  refresh();
}
