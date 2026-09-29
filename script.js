console.log('[Script] script.js carregado');

const API_BASE = '/api';
let authToken = sessionStorage.getItem('ap_authToken') || '';

// ====================== UTILITÁRIOS ======================

// Função segura para fazer fetch com tratamento de JSON
async function safeFetch(url, options = {}) {
  try {
    const response = await fetch(url, options);
    console.log(`[API] ${options.method || 'GET'} ${url} - Status: ${response.status}`);

    // Verificar status HTTP
    if (!response.ok) {
      const status = response.status;
      let errorMessage = `Erro HTTP ${response.status}: ${response.statusText}`;
      try {
        const errorText = await response.text();
        if (errorText && errorText.trim()) {
          try {
            const errorData = JSON.parse(errorText);
            errorMessage = errorData.error || errorMessage;
          } catch (parseError) {
            // Se não for JSON, usar o texto como mensagem de erro
            errorMessage = errorText.substring(0, 200); // Limitar tamanho
          }
        }
      } catch (textError) {
        console.warn('[API] Erro ao ler resposta de erro:', textError);
      }
      const error = new Error(errorMessage);
      error.status = status;
      if (status === 401 && !url.includes('/auth/login')) {
        expireSession();
      }
      throw error;
    }

    // Tentar fazer parse do JSON
    try {
      const responseText = await response.text();
      if (!responseText || responseText.trim() === '') {
        return {}; // Resposta vazia é tratada como objeto vazio
      }
      return JSON.parse(responseText);
    } catch (jsonError) {
      console.error('[API] Erro ao fazer parse do JSON:', jsonError);
      throw new Error('Resposta inválida do servidor (não é JSON válido)');
    }
  } catch (error) {
    console.error('[API] Erro na requisição:', error);
    throw error;
  }
}

function expireSession(){
  authToken = '';
  sessionStorage.removeItem('ap_authToken');
  loggedUser = null;
  if (typeof Store !== 'undefined') Store.clear();
  if (typeof renderAuthState === 'function') renderAuthState();
}


// Regex para validações
const REGEX_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const REGEX_CPF = /^\d{3}\.\d{3}\.\d{3}-\d{2}$/;
const REGEX_TELEFONE = /^\(\d{2}\)\d{4,5}-\d{4}$/;
const REGEX_SENHA = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

function sanitizeHTML(html) {
  if (typeof DOMPurify !== 'undefined' && DOMPurify && typeof DOMPurify.sanitize === 'function') {
    return DOMPurify.sanitize(html, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  }

  console.warn('[Sanitize] DOMPurify não está disponível. Usando fallback seguro.');
  const div = document.createElement('div');
  div.textContent = html;
  return div.innerHTML;
}

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function validateEmail(email) {
  return REGEX_EMAIL.test(email);
}

function validateCPF(cpf) {
  if (!REGEX_CPF.test(cpf)) return false;
  
  const clean = cpf.replace(/\D/g, '');
  if (clean === '00000000000' || clean === '11111111111' || clean === '22222222222' || 
      clean === '33333333333' || clean === '44444444444' || clean === '55555555555' ||
      clean === '66666666666' || clean === '77777777777' || clean === '88888888888' ||
      clean === '99999999999') return false;
  
  let sum = 0;
  for (let i = 1; i <= 9; i++) {
    sum += parseInt(clean.substring(i - 1, i)) * (11 - i);
  }
  let remainder = (sum * 10) % 11;
  if (remainder === 10 || remainder === 11) remainder = 0;
  if (remainder !== parseInt(clean.substring(9, 10))) return false;
  
  sum = 0;
  for (let i = 1; i <= 10; i++) {
    sum += parseInt(clean.substring(i - 1, i)) * (12 - i);
  }
  remainder = (sum * 10) % 11;
  if (remainder === 10 || remainder === 11) remainder = 0;
  return remainder === parseInt(clean.substring(10, 11));
}

function validateCellPhone(phone) {
  return REGEX_TELEFONE.test(phone);
}

function validatePassword(password) {
  return REGEX_SENHA.test(password);
}

// ====================== AUTENTICAÇÃO ======================
let loggedUser = null;

async function handleLogin(email, password) {
  try {
    email = email.trim().toLowerCase();

    if (!validateEmail(email)) {
      throw new Error('E-mail inválido.');
    }

    const result = await safeFetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (!result.success || !result.token || !result.user) {
      throw new Error(result.error || 'Falha no login');
    }

    loggedUser = {
      id: result.user.id,
      nome: result.user.nome,
      email: result.user.email,
      role: result.user.role,
      filialId: result.user.filialId || '',
      filialIds: result.user.filialIds || (result.user.filialId ? [result.user.filialId] : [])
    };

    authToken = result.token;
    sessionStorage.setItem('ap_authToken', authToken);
    Store.set('loggedUser', loggedUser);
    await hydrateFromDB();

    return { success: true, user: loggedUser };
  } catch (error) {
    console.error('[Auth]', error);
    return {
      success: false,
      error: 'E-mail ou senha inválidos.'
    };
  }
}

async function getAdminStatus() {
  return safeFetch(`${API_BASE}/auth/admin-status`);
}

function openModal(title, bodyHtml) {
  const overlay = document.getElementById('modal-overlay');
  if (!overlay) return;
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = bodyHtml;
  overlay.classList.add('open');
}

function setAdminCreationError(message) {
  const errorEl = document.getElementById('create-admin-error');
  if (errorEl) {
    errorEl.textContent = message || '';
  }
}

async function showAdminCreationForm() {
  const bodyHtml = `
    <div class="form-grid">
      <div class="form-group full"><label>Nome do administrador</label><input type="text" id="create-admin-name" placeholder="Administrador"></div>
      <div class="form-group full"><label>E-mail</label><input type="email" id="create-admin-email" placeholder="admin@academia.com"></div>
      <div class="form-group full"><label>Senha</label><input type="password" id="create-admin-password" placeholder="Senha segura"><small>Mínimo de 8 caracteres, com maiúscula, minúscula, número e símbolo.</small></div>
      <div class="form-group full"><label>Confirme a senha</label><input type="password" id="create-admin-password-confirm" placeholder="Repita a senha"></div>
      <div class="form-group full"><p id="create-admin-error" class="error-message"></p></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" type="button" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" type="button" onclick="submitAdminCreation()">Criar administrador</button>
    </div>`;
  openModal('Criar administrador', bodyHtml);
}

async function submitAdminCreation() {
  const nome = document.getElementById('create-admin-name')?.value.trim() || '';
  const email = document.getElementById('create-admin-email')?.value.trim().toLowerCase() || '';
  const password = document.getElementById('create-admin-password')?.value || '';
  const passwordConfirm = document.getElementById('create-admin-password-confirm')?.value || '';

  setAdminCreationError('');

  if (!nome || !email || !password || !passwordConfirm) {
    setAdminCreationError('Preencha todos os campos.');
    return;
  }

  if (!validateEmail(email)) {
    setAdminCreationError('E-mail inválido.');
    return;
  }

  if (!validatePassword(password)) {
    setAdminCreationError('Use 8 caracteres ou mais, incluindo maiúscula, minúscula, número e símbolo.');
    return;
  }

  if (password !== passwordConfirm) {
    setAdminCreationError('As senhas não coincidem.');
    return;
  }

  try {
    const result = await safeFetch(`${API_BASE}/auth/create-admin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nome, email, password })
    });

    if (!result.success) {
      setAdminCreationError(result.error || 'Não foi possível criar o administrador.');
      return;
    }

    closeModal();
    const helpEl = document.getElementById('login-help-text');
    if (helpEl) {
      helpEl.innerHTML = 'Administrador criado. Faça login com suas credenciais.';
    }
  } catch (error) {
    console.error('[Auth] Erro ao criar administrador:', error);
    setAdminCreationError('Erro ao criar administrador. Tente novamente.');
  }
}

function setPasswordResetError(message) {
  const errorEl = document.getElementById('password-reset-error');
  if (errorEl) {
    errorEl.textContent = message || '';
  }
}

function showPasswordResetForm() {
  const bodyHtml = `
    <div class="form-grid">
      <div class="form-group full"><label>E-mail</label><input type="email" id="reset-email" placeholder="gestor@academia.com"></div>
      <div class="form-group full"><label>Senha atual</label><input type="password" id="reset-current-password" placeholder="Senha atual"></div>
      <div class="form-group full"><label>Nova senha</label><input type="password" id="reset-new-password" placeholder="Nova senha"></div>
      <div class="form-group full"><label>Confirme a nova senha</label><input type="password" id="reset-new-password-confirm" placeholder="Repita a nova senha"></div>
      <div class="form-group full"><p id="password-reset-error" class="error-message"></p></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" type="button" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" type="button" onclick="submitPasswordReset()">Redefinir senha</button>
    </div>`;
  openModal('Redefinir senha', bodyHtml);
}

async function submitPasswordReset() {
  const email = document.getElementById('reset-email')?.value.trim().toLowerCase() || '';
  const currentPassword = document.getElementById('reset-current-password')?.value || '';
  const newPassword = document.getElementById('reset-new-password')?.value || '';
  const newPasswordConfirm = document.getElementById('reset-new-password-confirm')?.value || '';

  setPasswordResetError('');

  if (!email || !currentPassword || !newPassword || !newPasswordConfirm) {
    setPasswordResetError('Preencha todos os campos.');
    return;
  }

  if (!validateEmail(email)) {
    setPasswordResetError('E-mail inválido.');
    return;
  }

  if (newPassword.length < 8) {
    setPasswordResetError('A nova senha deve ter no mínimo 8 caracteres.');
    return;
  }

  if (newPassword !== newPasswordConfirm) {
    setPasswordResetError('As novas senhas não coincidem.');
    return;
  }

  try {
    const result = await safeFetch(`${API_BASE}/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, currentPassword, newPassword })
    });

    if (!result.success) {
      setPasswordResetError(result.error || 'Não foi possível redefinir a senha.');
      return;
    }

    closeModal();
    const helpEl = document.getElementById('login-help-text');
    if (helpEl) {
      helpEl.innerHTML = 'Senha atualizada com sucesso. Faça login com a nova senha.';
    }
  } catch (error) {
    console.error('[Auth] Erro ao redefinir senha:', error);
    setPasswordResetError('Erro ao redefinir a senha. Tente novamente.');
  }
}

async function refreshAdminCreationUI() {
  const helpEl = document.getElementById('login-help-text');
  if (!helpEl) return;

  try {
    const status = await getAdminStatus();
    if (status.setupRequired) {
      helpEl.innerHTML = 'Primeiro acesso? <button class="btn-link" type="button" onclick="showAdminCreationForm()">Criar administrador</button>';
    } else if (status.exists) {
      helpEl.innerHTML = 'Esqueceu a senha? <button class="btn-link" type="button" onclick="showPasswordResetForm()">Redefinir senha</button> | <strong>Consulte a equipe de Desenvolvimento</strong>';
    } else {
      helpEl.textContent = 'A configuração inicial já foi concluída. Consulte o administrador do sistema.';
    }
  } catch (error) {
    console.error('[Auth] Erro ao verificar status admin:', error);
    helpEl.textContent = 'Não foi possível verificar a configuração de acesso. Reinicie o aplicativo e tente novamente.';
  }
}

async function handleLogout() {
  authToken = '';
  sessionStorage.removeItem('ap_authToken');
  loggedUser = null;
  Store.clear();
  renderAuthState();
}

// ====================== STORE ======================

const Store = {
  data: {
    filiais: [],
    alunos: [],
    instrutores: [],
    mensalidades: [],
    despesas: [],
    eventos: [],
    turmas: [],
    presencas: [],
    users: []
  },

  keys: [
    'filiais', 'alunos', 'instrutores', 'mensalidades',
    'despesas', 'eventos', 'turmas', 'presencas', 'users'
  ],

  queues: {},
  initialized: false,

  init() {
    if (this.initialized) return;

    this.keys.forEach(key => {
      const raw = localStorage.getItem(`ap_data_${key}`);

      if (!raw) return;

      try {
        const value = JSON.parse(raw);
        if (Array.isArray(value)) this.data[key] = value;
      } catch {
        localStorage.removeItem(`ap_data_${key}`);
      }
    });

    this.initialized = true;
  },

  get(key) {
    this.init();

    if (this.keys.includes(key)) {
      return this.data[key] || [];
    }

    try {
      return JSON.parse(localStorage.getItem(`ap_${key}`));
    } catch {
      return null;
    }
  },

  set(key, value, options = {}) {
    this.init();

    if (this.keys.includes(key)) {
      this.data[key] = Array.isArray(value) ? value : [];

      localStorage.setItem(
        `ap_data_${key}`,
        JSON.stringify(this.data[key])
      );

      if (!options.skipRemote) {
        this.saveRemote(key);
      }

      return;
    }

    localStorage.setItem(`ap_${key}`, JSON.stringify(value));
  },

  setData(data) {
    this.init();

    this.keys.forEach(key => {
      if (Array.isArray(data?.[key])) {
        this.set(key, data[key], { skipRemote: true });
      }
    });
  },

  async saveRemote(key, options = {}) {
    if (!authToken) return;

    const previous = this.queues[key] || Promise.resolve();

    this.queues[key] = previous
      .catch(() => {})
      .then(async () => {
        await safeFetch(`${API_BASE}/db/save-table`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${authToken}`
          },
          body: JSON.stringify({ table: key, data: this.data[key] })
        });
      })
      .catch(error => {
        console.warn(`[Store] ${key} salvo localmente:`, error.message);
        if (options.throwOnError) throw error;
      });

    return this.queues[key];
  },

  clear() {
    this.keys.forEach(key => {
      this.data[key] = [];
      localStorage.removeItem(`ap_data_${key}`);
    });

    localStorage.removeItem('ap_loggedUser');
    localStorage.removeItem('ap_seeded');
  }
};

async function dbLoadAll() {
  if (!authToken) return {};

  return safeFetch(`${API_BASE}/db/load`, {
    headers: { Authorization: `Bearer ${authToken}` }
  });
}

async function hydrateFromDB() {
  Store.init();

  try {
    const remoteData = await dbLoadAll();

    if (Object.keys(remoteData).length) {
      Store.setData(remoteData);
    } else {
      for (const key of Store.keys) {
        if (Store.get(key).length) {
          await Store.saveRemote(key);
        }
      }
    }
  } catch (error) {
    if (error.status === 401) expireSession();
    console.warn('[Supabase] Dados locais utilizados:', error.message);
  }
}

// ====================== SEED ======================
async function seedData(){
  if (Store.get('seeded')) return;
  Store.set('seeded', true);
}

// ====================== ROUTER ======================
const ROUTES={dashboard:'DASHBOARD',filiais:'ASSOCIAÇÕES',alunos:'ALUNOS',instrutores:'INSTRUTORES & PROFESSORES',usuarios:'USUÁRIOS',turmas:'TURMAS & HORÁRIOS',financeiro:'FINANCEIRO',eventos:'EVENTOS',presenca:'PRESENÇA & FREQUÊNCIA',relatorios:'RELATÓRIOS'};
const SUBS={dashboard:'Visão geral do sistema',filiais:'Gerencie as associações da academia',alunos:'Controle de matrículas por associação',instrutores:'Equipe técnica das associações',usuarios:'Controle de contas e níveis de acesso',turmas:'Grade de aulas e horários por associação',financeiro:'Mensalidades, despesas e fluxo de caixa',eventos:'Campeonatos, seminários e graduações',presenca:'Chamada diária e análise de frequência dos alunos',relatorios:'Análises detalhadas por associação'};

function navigate(route){
  console.log('[Navigate] Mudando para rota:', route);
  location.hash='#'+route;
  console.log('[Navigate] Hash atualizado para:', location.hash);
}

function route(){
  console.log('[Route] ▶ ROTA ACIONADA, hash:', location.hash);
  console.log('[Route] Usuario logado:', getLoggedUser() ? getLoggedUser().nome : 'NENHUM');
  
  if(!getLoggedUser()){
    console.log('[Route] ✗ Usuário não logado, redirecionando para login');
    if(location.hash!=='#login')location.hash='#login';
    return;
  }
  
  const hash=(location.hash||'#dashboard').replace('#','');
  console.log('[Route] Hash parseado:', hash);
  
  if(!hasAccess(hash)){
    console.warn('[Route] ✗ Acesso negado para:', hash);
    if(location.hash!=='#dashboard')navigate('dashboard');
    return;
  }
  
  console.log('[Route] ✓ Acesso permitido, atualizando UI...');
  console.log('[Route] - Removendo classes "active" de todas as seções');
  document.querySelectorAll('.section').forEach(s=>{
    if(s.classList.contains('active')){
      console.log('[Route]   - Removido active de:', s.id);
    }
    s.classList.remove('active');
  });
  
  console.log('[Route] - Atualizando nav items');
  document.querySelectorAll('.nav-item').forEach(n=>{
    const isActive = n.dataset.route === hash;
    n.classList.toggle('active', isActive);
    if(isActive) console.log('[Route]   - Selecionado:', n.dataset.route);
  });
  
  const sec=document.getElementById('sec-'+hash);
  console.log('[Route] - Procurando seção:', 'sec-'+hash, !sec ? '✗ NÃO ENCONTRADA' : '✓ encontrada');
  if(sec){
    sec.classList.add('active');
    console.log('[Route]   - Ativada');
  } else {
    console.warn('[Route] ✗✗✗ SEÇÃO NÃO ENCONTRADA: sec-' + hash);
    console.log('[Route] Seções disponíveis:', Array.from(document.querySelectorAll('.section')).map(s => s.id).join(', '));
  }
  
  console.log('[Route] - Atualizando header...');
  const headerTitle = document.getElementById('header-title');
  const headerSub = document.getElementById('header-sub');
  if(headerTitle) headerTitle.textContent = ROUTES[hash] || hash.toUpperCase();
  if(headerSub) headerSub.textContent = SUBS[hash] || '';
  
  // Hide aluno profile on navigate away
  if(hash!=='alunos'){
    const p=document.getElementById('aluno-profile');
    if(p){
      p.style.display='none';
      const al = document.getElementById('alunos-list');
      if(al) al.style.display='block';
    }
  }
  
  console.log('[Route] - Chamando renderPage(' + hash + ')');
  try {
    renderPage(hash);
    console.log('[Route] ◀ ✓ ROTA COMPLETA');
  } catch (error) {
    console.error('[Route] ◀ ✗✗✗ ERRO NA ROTA:', error);
    console.error(error.stack);
  }
}

function renderPage(hash){
  console.log('[RenderPage] ▶▶▶ RENDERIZANDO PÁGINA:', hash);
  try {
    console.log('[RenderPage] Função existe?', typeof window[`render${hash.charAt(0).toUpperCase() + hash.slice(1)}`]);
    switch(hash){
      case'dashboard':
        console.log('[RenderPage] • renderDashboard');
        renderDashboard();
        console.log('[RenderPage] ✓ dashboard renderizado');
        break;
      case'filiais':
        console.log('[RenderPage] • renderFiliais');
        renderFiliais();
        console.log('[RenderPage] ✓ filiais renderizadas');
        break;
      case'alunos':
        console.log('[RenderPage] • renderAlunos (dados:', getAlunos().length, 'itens)');
        renderAlunos();
        console.log('[RenderPage] ✓ alunos renderizados');
        break;
      case'instrutores':
        console.log('[RenderPage] • renderInstrutores');
        renderInstrutores();
        console.log('[RenderPage] ✓ instrutores renderizados');
        break;
      case'usuarios':
        console.log('[RenderPage] • renderUsuarios');
        renderUsuarios();
        console.log('[RenderPage] ✓ usuários renderizados');
        break;
      case'turmas':
        console.log('[RenderPage] • renderTurmas');
        renderTurmas();
        renderGradeSemanal();
        console.log('[RenderPage] ✓ turmas renderizadas');
        break;
      case'financeiro':
        console.log('[RenderPage] • renderMensalidades, renderDespesas, renderFluxo');
        renderMensalidades();
        renderDespesas();
        renderFluxo();
        console.log('[RenderPage] ✓ financeiro renderizado');
        break;
      case'eventos':
        console.log('[RenderPage] • renderEventos, renderCalendario');
        renderEventos();
        renderCalendario();
        console.log('[RenderPage] ✓ eventos renderizados');
        break;
      case'presenca':
        console.log('[RenderPage] • initPresenca');
        initPresenca();
        console.log('[RenderPage] ✓ presença inicializada');
        break;
      case'relatorios':
        console.log('[RenderPage] • renderRelatorios');
        renderRelatorioFilial();
        renderRelatorioConsolidado();
        renderRelatorioFinanceiro();
        renderRelatorioInstrutores();
        console.log('[RenderPage] ✓ relatórios renderizados');
        break;
      default:
        console.warn('[RenderPage] ✗ Hash não reconhecido:', hash);
    }
    console.log('[RenderPage] • updateAlertCount');
    updateAlertCount();
    console.log('[RenderPage] • populateFilialSelects');
    populateFilialSelects();
    console.log('[RenderPage] ◀◀◀ ✓ RENDERIZAÇÃO COMPLETA:', hash);
  } catch (error) {
    console.error('[RenderPage] ◀◀◀ ✗✗✗ ERRO AO RENDERIZAR:', hash);
    console.error('[RenderPage] Erro:', error);
    console.error('[RenderPage] Stack:', error.stack);
  }
}

function getLoggedUser(){return Store.get('loggedUser');}
function getUsers(){return Store.get('users')||[];}
function authenticate(event){
  if(event && event.preventDefault) event.preventDefault();
  const email=document.getElementById('login-email').value.trim();
  const password=document.getElementById('login-password').value;
  
  handleLogin(email, password).then(result => {
    if (result.success) {
      renderAuthState();
    } else {
      alert(result.error || 'Erro no login');
    }
  }).catch(error => {
    console.error('Erro no login:', error);
    alert('Erro interno no login');
  });
  return false;
}
function logout(){handleLogout(); renderAuthState();}
function renderUsuarios(){
  const q=(document.getElementById('usuarios-search')||{}).value||'';
  const role=(document.getElementById('usuarios-role-filter')||{}).value||'';
  let data=getUsers();
  if(role)data=data.filter(u=>u.role===role);
  if(q)data=data.filter(u=>u.nome.toLowerCase().includes(q.toLowerCase())||u.email.toLowerCase().includes(q.toLowerCase()));
  const tb=document.getElementById('usuarios-tbody');if(!tb)return;
  if(!data.length){tb.innerHTML=`<tr><td colspan="5"><div class="empty-state"><p>Nenhum usuário encontrado</p></div></td></tr>`;return;}
  tb.innerHTML=data.map(u=>`<tr>
    <td><strong>${escapeHTML(u.nome)}</strong></td>
    <td>${escapeHTML(u.email)}</td>
    <td>${escapeHTML(u.role)}</td>
    <td>${u.role==='Administrador'?'Todas':(u.filialIds||[u.filialId].filter(Boolean)).map(filialNome).map(escapeHTML).join(', ')||'—'}</td>
    <td>${isAdmin()?`<button class="btn btn-secondary btn-sm" onclick="openModalUsuario(${escapeHTML(JSON.stringify(u.id))})">Editar</button> <button class="btn btn-danger btn-sm" onclick="deleteUsuario(${escapeHTML(JSON.stringify(u.id))})">Excluir</button>`:'<button class="btn btn-secondary btn-sm" disabled aria-disabled="true" title="Apenas administradores podem editar usuários">Editar</button> <span class="badge badge-gray">Somente leitura</span>'}</td>
  </tr>`).join('');
}
function openModalUsuario(id){
  if(!isAdmin())return alert('Apenas administradores podem gerenciar usuários');
  const u=id?getUsers().find(x=>x.id===id):{};
  const userBranchIds=u.filialIds||[u.filialId].filter(Boolean);
  document.getElementById('modal-title').textContent=id?'EDITAR USUÁRIO':'NOVO USUÁRIO';
  document.getElementById('modal-body').innerHTML=`
    <div class="form-grid">
      <div class="form-group full"><label>Nome</label><input type="text" id="u-nome" value="${escapeHTML(u.nome||'')}"></div>
      <div class="form-group full"><label>E-mail</label><input type="email" id="u-email" value="${escapeHTML(u.email||'')}"></div>
      <div class="form-group full"><label>Senha${id?' (deixe em branco para manter atual)':''}</label><input type="password" id="u-senha" placeholder="${id?'Deixe em branco para manter senha atual':'Digite a senha'}"></div>
      <div class="form-group full"><label>Nível</label><select id="u-role" onchange="toggleUserBranchSelector()"><option${u.role==='Administrador'?' selected':''}>Administrador</option><option${u.role==='Gestor'?' selected':''}>Gestor</option></select></div>
      <div class="form-group full" id="u-branch-group"><label>Associações do gestor <span aria-hidden="true">*</span></label><div class="association-checkbox-list" role="group" aria-label="Associações do gestor">${getFiliais().map(f=>`<label class="association-checkbox-option" for="u-filial-${escapeHTML(f.id)}"><input type="checkbox" id="u-filial-${escapeHTML(f.id)}" name="u-filiais" value="${escapeHTML(f.id)}"${userBranchIds.includes(f.id)?' checked':''}> <span>${escapeHTML(f.nome)}</span></label>`).join('')||'<p class="association-checkbox-empty">Nenhuma associação cadastrada.</p>'}</div><small>Obrigatório: marque uma ou mais associações.</small></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveUsuario(${escapeHTML(JSON.stringify(id||''))})">Salvar</button>
    </div>`;
  document.getElementById('modal-overlay').classList.add('open');
  toggleUserBranchSelector();
}
function toggleUserBranchSelector(){
  const group=document.getElementById('u-branch-group');
  const role=document.getElementById('u-role');
  if(group&&role)group.style.display=role.value==='Gestor'?'block':'none';
}
async function saveUsuario(id){
  if(!isAdmin())return alert('Apenas administradores podem gerenciar usuários');
  const nome=document.getElementById('u-nome').value.trim();
  const email=document.getElementById('u-email').value.trim();
  const senha=document.getElementById('u-senha').value;
  const role=document.getElementById('u-role').value;
  const filialIds=[...document.querySelectorAll('input[name="u-filiais"]:checked')].map(input=>input.value);
  if(!nome||!email||!role)return alert('Preencha nome, email e nível');
  if(role==='Gestor'&&!filialIds.length){
    alert('Associe o gestor a pelo menos uma associação');
    document.querySelector('input[name="u-filiais"]')?.focus();
    return;
  }
  if(!id && !senha)return alert('Senha é obrigatória para novos usuários');

  try {
    let updateData;
    if(id){
      updateData = { nome, email, role, filialIds: role === 'Gestor' ? filialIds : [] };
      if(senha) updateData.password = senha;
    }

    const result = await safeFetch(id ? `${API_BASE}/users/${id}` : `${API_BASE}/users/create`, {
      method: id ? 'PUT' : 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`
      },
      body: JSON.stringify(id ? updateData : { nome, email, password: senha, role, filialIds: role === 'Gestor' ? filialIds : [] })
    });

    if(!result.success) throw new Error(result.error || 'Erro ao salvar usuário');

    if(result.success){
      alert(id ? 'Usuário atualizado com sucesso!' : 'Usuário criado com sucesso!');
      closeModal();
      // Reload users data and re-render
      Store.setData(await dbLoadAll());
      renderUsuarios();
    }
  } catch (error) {
    console.error('Erro ao salvar usuário:', error);
    alert('Erro ao salvar usuário: ' + error.message);
  }
}
async function deleteUsuario(id){
  if(!isAdmin())return alert('Apenas administradores podem excluir usuários');
  if(!confirm('Excluir este usuário? Esta ação não pode ser desfeita.'))return;

  try {
    const result = await safeFetch(`${API_BASE}/users/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if(!result.success) throw new Error(result.error || 'Erro ao excluir usuário');

    if(result.success){
      alert('Usuário excluído com sucesso!');
      // Reload users data and re-render
      Store.setData(await dbLoadAll());
      renderUsuarios();
    }
  } catch (error) {
    console.error('Erro ao excluir usuário:', error);
    alert('Erro ao excluir usuário: ' + error.message);
  }
}

function isAdmin(){const u=getLoggedUser();return u&&u.role==='Administrador';}
function hasAccess(route){const user=getLoggedUser();if(!user)return false; if(route==='financeiro')return isAdmin(); if(route==='instrutores')return isAdmin(); if(route==='usuarios')return isAdmin(); if(route==='relatorios')return isAdmin(); return true;}
function renderAuthState(){
  const user=getLoggedUser();
  const loginScreen=document.getElementById('login-screen');
  const sidebar=document.getElementById('sidebar');
  const main=document.getElementById('main');
  const logoutBtn=document.getElementById('logout-btn');
  const headerUser=document.getElementById('header-user');
  const financeNav=document.querySelector('.nav-item[data-route="financeiro"]');
  const instrutoresNav=document.querySelector('.nav-item[data-route="instrutores"]');
  const usuariosNav=document.querySelector('.nav-item[data-route="usuarios"]');
  const relatoriosNav=document.querySelector('.nav-item[data-route="relatorios"]');
  const instAdd=document.getElementById('inst-add-btn');
  const userAdd=document.getElementById('usuarios-add-btn');
  const filialAdd=document.getElementById('filial-add-btn');
  if(user){
    document.body.classList.remove('logged-out');
    loginScreen.style.display='none';
    sidebar.style.display='flex';
    main.style.display='flex';
    headerUser.style.display='inline-block';
    headerUser.textContent=`${user.nome} (${user.role})`;
    logoutBtn.style.display='inline-flex';
    if(financeNav)financeNav.style.display=isAdmin()?'flex':'none';
    if(instrutoresNav)instrutoresNav.style.display=isAdmin()?'flex':'none';
    if(usuariosNav)usuariosNav.style.display=isAdmin()?'flex':'none';
    if(relatoriosNav)relatoriosNav.style.display=isAdmin()?'flex':'none';
    if(instAdd)instAdd.style.display=isAdmin()?'inline-flex':'none';
    if(userAdd)userAdd.style.display=isAdmin()?'inline-flex':'none';
    if(filialAdd)filialAdd.style.display=isAdmin()?'inline-flex':'none';
    if(!location.hash||location.hash==='#login')navigate('dashboard');
    else route();
  } else {
    document.body.classList.add('logged-out');
    loginScreen.style.display='flex';
    sidebar.style.display='none';
    main.style.display='none';
    if(headerUser)headerUser.style.display='none';
    if(logoutBtn)logoutBtn.style.display='none';
    if(location.hash!=='#login')location.hash='#login';
  }
}
async function clearData() {
  if (!confirm('Tem certeza que deseja limpar todos os dados salvos?')) {
    return;
  }

  Store.clear();

  try {
    await safeFetch(`${API_BASE}/db/clear-all`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` }
    });
  } catch (error) {
    console.error('[API] Erro ao limpar dados:', error);
    alert('Dados locais limpos, mas houve erro no banco remoto.');
    return;
  }

  alert('Dados limpos com sucesso.');
  location.reload();
}

// ====================== HELPERS ======================
function uid(){return'x'+Math.random().toString(36).substr(2,9);}
function fmt(v){return'R$ '+Number(v).toLocaleString('pt-BR',{minimumFractionDigits:2});}
function fmtDate(d){if(!d)return'-';const[y,m,dd]=d.split('-');return`${dd}/${m}/${y}`;}
function filialNome(id){const f=getFiliais().find(x=>x.id===id);return f?f.nome:'—';}
function alunoNome(id){const a=getAlunos().find(x=>x.id===id);return a?a.nome:'—';}
function getFiliais(){return Store.get('filiais')||[];}
function getAlunos(){return Store.get('alunos')||[];}
function getInstrutores(){return Store.get('instrutores')||[];}
function getMensalidades(){return Store.get('mensalidades')||[];}
function getDespesas(){return Store.get('despesas')||[];}
function getEventos(){return Store.get('eventos')||[];}
function getGlobalFilial(){return document.getElementById('filial-global')?.value||'all';}

function getList(key){return Store.get(key)||[];}
function saveListItem(key,id,item){
  const list=getList(key);
  if(id){
    const index=list.findIndex(x=>x.id===id);
    if(index>=0) list[index]=item;
    else list.push(item);
  } else {
    list.push(item);
  }
  Store.set(key,list);
  return list;
}
function deleteListItem(key,id){
  const list=getList(key).filter(x=>x.id!==id);
  Store.set(key,list);
  return list;
}

async function debugPersistence(){
  console.log('[Debug] Persistência: estado do Store');
  Store.keys.forEach((key)=>{
    const value=Store.get(key);
    console.log(`  ${key}:`, Array.isArray(value)?value.length:value, value);
  });
  try {
    const dbData = await dbLoadAll();
    console.log('[Debug] Dados carregados do servidor:', dbData);
  } catch (error) {
    console.error('[Debug] Erro ao carregar dados:', error);
  }
}

function getCheckedValues(selector){
  return [...document.querySelectorAll(selector)].filter(el=>el.checked).map(el=>el.value);
}

function renderPagination(containerId, page, totalPages, totalItems, onPageChange){
  const container=document.getElementById(containerId);
  if(!container)return;
  if(totalItems===0||totalPages<=1){
    container.innerHTML=totalItems?`<span>${totalItems} aluno(s)</span>`:'';
    return;
  }
  const previousDisabled=page<=1?' disabled':'';
  const nextDisabled=page>=totalPages?' disabled':'';
  container.innerHTML=`
    <span>${totalItems} aluno(s) — página ${page} de ${totalPages}</span>
    <div style="display:flex;gap:8px">
      <button class="btn btn-secondary btn-sm"${previousDisabled}>Anterior</button>
      <button class="btn btn-secondary btn-sm"${nextDisabled}>Próxima</button>
    </div>`;
  const buttons=container.querySelectorAll('button');
  buttons[0]?.addEventListener('click',()=>onPageChange(page-1));
  buttons[1]?.addEventListener('click',()=>onPageChange(page+1));
}

function statusBadge(s){
  const m={Ativo:'badge-green',Inativo:'badge-red',Suspenso:'badge-orange','Em Atraso':'badge-red',Pendente:'badge-yellow',Pago:'badge-green',Professor:'badge-blue',Instrutor:'badge-yellow'};
  return`<span class="badge ${m[s]||'badge-gray'}">${s}</span>`;
}

function updateAlertCount(){
  const cnt=getMensalidades().filter(m=>m.status==='Em Atraso').length;
  document.getElementById('alert-count').textContent=cnt;
}

function populateFilialSelects(){
  const filiais=getFiliais();
  const globalSel=document.getElementById('filial-global');
  const cur=globalSel.value;
  globalSel.innerHTML='<option value="all">Todas as Associações</option>'+filiais.map(f=>`<option value="${f.id}">${f.nome}</option>`).join('');
  globalSel.value=cur||'all';

  ['alunos-fil-filter','inst-fil-filter','mens-fil-filter','desp-fil-filter','ev-fil-filter','turmas-fil-filter','turmas-grade-filial','pres-fil-chamada','pres-freq-fil'].forEach(id=>{
    const el=document.getElementById(id);
    if(el){
      const v=el.value;
      el.innerHTML='<option value="">Todas as Associações</option>'+filiais.map(f=>`<option value="${f.id}">${f.nome}</option>`).join('');
      el.value=v||'';
    }
  });
}

// ====================== DASHBOARD ======================
function renderDashboard(){
  const alunos=getAlunos();
  const mens=getMensalidades();
  const desp=getDespesas();
  const filiais=getFiliais();
  const ativos=alunos.filter(a=>a.status==='Ativo').length;
  const inativos=alunos.filter(a=>a.status!=='Ativo').length;
  const receita=mens.filter(m=>m.status==='Pago').reduce((s,m)=>s+Number(m.valor),0);
  const despTotal=desp.reduce((s,d)=>s+Number(d.valor),0);
  const inadimp=mens.filter(m=>m.status==='Em Atraso').length;

  document.getElementById('dash-kpis').innerHTML=`
    <div class="card"><div class="card-label">Alunos Ativos</div><div class="card-value">${ativos}</div><div class="card-sub">de ${alunos.length} matrículas</div></div>
    <div class="card card-yellow"><div class="card-label">Alunos Inativos</div><div class="card-value">${inativos}</div><div class="card-sub">Inativo + Suspenso</div></div>
    <div class="card card-green"><div class="card-label">Receita (Mês)</div><div class="card-value" style="font-size:28px">${fmt(receita)}</div><div class="card-sub">mensalidades pagas</div></div>
    <div class="card card-red"><div class="card-label">Inadimplentes</div><div class="card-value">${inadimp}</div><div class="card-sub">mensalidades em atraso</div></div>
  `;

  const maxA=Math.max(...filiais.map(f=>alunos.filter(a=>a.filialId===f.id).length),1);
  document.getElementById('dash-chart-alunos').innerHTML=filiais.map(f=>{
    const cnt=alunos.filter(a=>a.filialId===f.id).length;
    const h=Math.round((cnt/maxA)*100);
    return`<div class="chart-bar-col"><div class="chart-val">${cnt}</div><div class="chart-bar" style="height:${h}px;background:linear-gradient(180deg,var(--orange),var(--yellow))"></div><div class="chart-label">${f.nome}</div></div>`;
  }).join('');

  const maxF=Math.max(...filiais.map(f=>{
    const r=mens.filter(m=>m.filialId===f.id&&m.status==='Pago').reduce((s,m)=>s+m.valor,0);
    const d=desp.filter(x=>x.filialId===f.id).reduce((s,x)=>s+x.valor,0);
    return Math.max(r,d);
  }),1);
  document.getElementById('dash-chart-fin').innerHTML=filiais.map(f=>{
    const r=mens.filter(m=>m.filialId===f.id&&m.status==='Pago').reduce((s,m)=>s+m.valor,0);
    const d=desp.filter(x=>x.filialId===f.id).reduce((s,x)=>s+x.valor,0);
    const hr=Math.round((r/maxF)*100);const hd=Math.round((d/maxF)*100);
    return`<div class="chart-bar-col" style="flex:2;gap:2px">
      <div style="display:flex;gap:2px;align-items:flex-end;height:100px">
        <div class="chart-bar" style="flex:1;height:${hr}px;background:var(--green)"></div>
        <div class="chart-bar" style="flex:1;height:${hd}px;background:var(--red)"></div>
      </div>
      <div class="chart-label">${f.nome}</div>
    </div>`;
  }).join('');

  document.getElementById('dash-filiais-cards').innerHTML=filiais.map(f=>{
    const fa=alunos.filter(a=>a.filialId===f.id);
    const at=fa.filter(a=>a.status==='Ativo').length;
    const inAt=fa.filter(a=>a.status!=='Ativo').length;
    const rec=mens.filter(m=>m.filialId===f.id&&m.status==='Pago').reduce((s,m)=>s+m.valor,0);
    const pct=fa.length?Math.round(at/fa.length*100):0;
    return`<div class="card" style="cursor:pointer" onclick="navigate('alunos');document.getElementById('alunos-fil-filter').value='${f.id}';renderAlunos()">
      <div class="card-label">${f.nome}</div>
      <div style="display:flex;gap:16px;margin:10px 0">
        <div><div style="font-family:'Bebas Neue',sans-serif;font-size:28px;color:var(--green)">${at}</div><div style="font-size:11px;color:var(--gray)">Ativos</div></div>
        <div><div style="font-family:'Bebas Neue',sans-serif;font-size:28px;color:var(--red)">${inAt}</div><div style="font-size:11px;color:var(--gray)">Inativos</div></div>
        <div><div style="font-family:'Bebas Neue',sans-serif;font-size:24px;color:var(--orange)">${fmt(rec)}</div><div style="font-size:11px;color:var(--gray)">Receita</div></div>
      </div>
      <div class="stat-bar-wrap"><div class="stat-bar-label"><span>Retenção</span><span>${pct}%</span></div><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:${pct}%"></div></div></div>
    </div>`;
  }).join('');
}

// ====================== ASSOCIAÇÕES ======================
function renderFiliais(){
  const q=(document.getElementById('filiais-search')||{}).value||'';
  const data=getFiliais().filter(f=>f.nome.toLowerCase().includes(q.toLowerCase())||f.cidade.toLowerCase().includes(q.toLowerCase()));
  const tb=document.getElementById('filiais-tbody');
  if(!tb)return;
  if(!data.length){tb.innerHTML=`<tr><td colspan="6"><div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg><p>Nenhuma associação cadastrada</p></div></td></tr>`;return;}
  tb.innerHTML=data.map(f=>`<tr>
    <td><strong>${f.nome}</strong><br><span style="font-size:11px;color:var(--gray)">${f.endereco}</span></td>
    <td>${f.cidade}</td><td>${f.responsavel}</td>
    <td>${(f.modalidades||[]).map(m=>`<span class="badge badge-orange" style="margin:1px">${m}</span>`).join('')}</td>
    <td>${statusBadge(f.status)}</td>
    <td>${isAdmin()?`<button class="btn btn-secondary btn-sm" onclick="openModalFilial(${escapeHTML(JSON.stringify(f.id))})">Editar</button> <button class="btn btn-danger btn-sm" onclick="deleteFilial(${escapeHTML(JSON.stringify(f.id))})">Excluir</button>`:'<button class="btn btn-secondary btn-sm" disabled aria-disabled="true" title="Apenas administradores podem editar associações">Editar</button> <button class="btn btn-danger btn-sm" disabled aria-disabled="true" title="Apenas administradores podem excluir associações">Excluir</button>'}</td>
  </tr>`).join('');
}

function deleteFilial(id){
  if(!isAdmin())return alert('Apenas administradores podem excluir associações');
  if(!confirm('Excluir esta associação?'))return;
  deleteListItem('filiais',id);
  renderFiliais();populateFilialSelects();
}

function openModalFilial(id){
  if(!isAdmin())return alert('Apenas administradores podem gerenciar associações');
  const f=id?getFiliais().find(x=>x.id===id):{};
  const mods=['Kung-Fu','Boxe Chines','Thai Chi'];
  document.getElementById('modal-title').textContent=id?'EDITAR ASSOCIAÇÃO':'NOVA ASSOCIAÇÃO';
  document.getElementById('modal-body').innerHTML=`
    <div class="form-grid">
      <div class="form-group full"><label>Nome da Associação</label><input type="text" id="f-nome" value="${f.nome||''}"></div>
      <div class="form-group full"><label>Endereço</label><input type="text" id="f-end" value="${f.endereco||''}"></div>
      <div class="form-group"><label>Cidade</label><input type="text" id="f-cidade" value="${f.cidade||''}"></div>
      <div class="form-group"><label>Responsável</label><input type="text" id="f-resp" value="${f.responsavel||''}"></div>
      <div class="form-group"><label>Status</label><select id="f-status">${['Ativo','Inativo'].map(s=>`<option${f.status===s?' selected':''}>${s}</option>`).join('')}</select></div>
      <div class="form-group"><label>Modalidades</label><div style="display:flex;flex-direction:column;gap:4px;margin-top:4px">${mods.map(m=>`<label style="display:flex;align-items:center;gap:6px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;color:var(--dark)"><input type="checkbox" value="${m}" ${(f.modalidades||[]).includes(m)?'checked':''}> ${m}</label>`).join('')}</div></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveFilial('${id||''}')">Salvar</button>
    </div>`;
  document.getElementById('modal-overlay').classList.add('open');
}

function saveFilial(id){
  if(!isAdmin())return alert('Apenas administradores podem gerenciar associações');
  const nome=document.getElementById('f-nome').value.trim();
  if(!nome)return alert('Informe o nome da associação');
  const mods=getCheckedValues('#modal-body input[type=checkbox]:checked');
  const obj={id:id||uid(),nome,endereco:document.getElementById('f-end').value,cidade:document.getElementById('f-cidade').value,responsavel:document.getElementById('f-resp').value,modalidades:mods,status:document.getElementById('f-status').value};
  saveListItem('filiais',id,obj);
  closeModal();renderFiliais();populateFilialSelects();renderDashboard();
}

// ====================== ALUNOS ======================
function renderAlunos(page = 1, pageSize = 20){
  const q=(document.getElementById('alunos-search')||{}).value||'';
  const fil=(document.getElementById('alunos-fil-filter')||{}).value||'';
  const st=(document.getElementById('alunos-status-filter')||{}).value||'';
  const mod=(document.getElementById('alunos-mod-filter')||{}).value||'';
  const gf=getGlobalFilial();
  let data=getAlunos();
  if(gf!=='all')data=data.filter(a=>a.filialId===gf);
  if(fil)data=data.filter(a=>a.filialId===fil);
  if(st)data=data.filter(a=>a.status===st);
  if(mod)data=data.filter(a=>a.modalidade===mod);
  if(q)data=data.filter(a=>a.nome.toLowerCase().includes(q.toLowerCase())||a.cpf.includes(q));
  
  // Paginação
  const totalItems = data.length;
  const totalPages = Math.ceil(totalItems / pageSize);
  const startIndex = (page - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedData = data.slice(startIndex, endIndex);
  
  const tb=document.getElementById('alunos-tbody');
  if(!tb)return;
  if(!paginatedData.length){tb.innerHTML=`<tr><td colspan="7"><div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/></svg><p>Nenhum aluno encontrado</p></div></td></tr>`;return;}
  tb.innerHTML=paginatedData.map(a=>`<tr onclick="showAlunoProfile('${a.id}')">
    <td><strong>${a.nome}</strong></td>
    <td>${filialNome(a.filialId)}</td>
    <td>${a.modalidade}</td>
    <td><span class="badge badge-yellow">${a.faixa}</span></td>
    <td>${statusBadge(a.status)}</td>
    <td>${fmtDate(a.matricula)}</td>
    <td onclick="event.stopPropagation()"><button class="btn btn-secondary btn-sm" onclick="openModalAluno('${a.id}')">Editar</button> <button class="btn btn-danger btn-sm" onclick="deleteAluno('${a.id}')">Excluir</button></td>
  </tr>`).join('');
  
  // Renderizar controles de paginação
  renderPagination('alunos-pagination', page, totalPages, totalItems, (newPage) => renderAlunos(newPage, pageSize));
}

function showAlunoProfile(id){
  const a=getAlunos().find(x=>x.id===id);if(!a)return;
  const pags=getMensalidades().filter(m=>m.alunoId===id);
  document.getElementById('alunos-list').style.display='none';
  const p=document.getElementById('aluno-profile');
  p.style.display='block';
  p.innerHTML=`
    <button class="btn btn-secondary" style="margin-bottom:16px" onclick="document.getElementById('aluno-profile').style.display='none';document.getElementById('alunos-list').style.display='block'">← Voltar</button>
    <div class="profile-card">
      <div class="profile-info">
        <div class="profile-avatar">${a.nome[0]}</div>
        <div><h3>${a.nome}</h3><p>${a.modalidade} — ${filialNome(a.filialId)}</p></div>
        <div style="margin-left:auto">${statusBadge(a.status)}</div>
      </div>
      <div class="profile-fields">
        <div class="pf-item"><label>CPF</label><p>${a.cpf}</p></div>
        <div class="pf-item"><label>Nascimento</label><p>${fmtDate(a.nascimento)}</p></div>
        <div class="pf-item"><label>Telefone</label><p>${a.telefone}</p></div>
        <div class="pf-item"><label>E-mail</label><p>${a.email}</p></div>
        <div class="pf-item"><label>Faixa/Graduação</label><p><span class="badge badge-yellow">${a.faixa}</span></p></div>
        <div class="pf-item"><label>Matrícula</label><p>${fmtDate(a.matricula)}</p></div>
      </div>
    </div>
    <div class="profile-card">
      <div class="report-title">Histórico de Pagamentos</div>
      ${pags.length?`<div class="table-wrap"><table><thead><tr><th>Referência</th><th>Vencimento</th><th>Valor</th><th>Método</th><th>Status</th></tr></thead><tbody>${pags.map(m=>`<tr><td>${m.referencia}</td><td>${fmtDate(m.vencimento)}</td><td>${fmt(m.valor)}</td><td>${m.metodo}</td><td>${statusBadge(m.status)}</td></tr>`).join('')}</tbody></table></div>`:'<p style="color:var(--gray);font-size:13px">Nenhum pagamento registrado</p>'}
    </div>`;
}

function deleteAluno(id){
  if(!confirm('Excluir este aluno?'))return;
  deleteListItem('alunos',id);renderAlunos();renderDashboard();
}

function openModalAluno(id){
  const a=id?getAlunos().find(x=>x.id===id):{};
  const filiais=getFiliais();
  const faixas=['Branca','Laranja','Vermelha','Azul','Marrom','Preta'];
  document.getElementById('modal-title').textContent=id?'EDITAR ALUNO':'NOVO ALUNO';
  document.getElementById('modal-body').innerHTML=`
    <div class="form-grid">
      <div class="form-group full"><label>Nome Completo</label><input type="text" id="a-nome" value="${a.nome||''}"></div>
      <div class="form-group"><label>CPF</label><input type="text" id="a-cpf" value="${a.cpf||''}"></div>
      <div class="form-group"><label>Data de Nascimento</label><input type="date" id="a-nasc" value="${a.nascimento||''}"></div>
      <div class="form-group"><label>Telefone</label><input type="tel" id="a-tel" value="${a.telefone||''}"></div>
      <div class="form-group"><label>E-mail</label><input type="email" id="a-email" value="${a.email||''}"></div>
      <div class="form-group"><label>Associação</label><select id="a-filial">${filiais.map(f=>`<option value="${f.id}"${a.filialId===f.id?' selected':''}>${f.nome}</option>`).join('')}</select></div>
      <div class="form-group"><label>Modalidade</label><select id="a-mod"><option>Kung-Fu</option><option>Boxe Chines</option><option>Thai Chi</option></select></div>
      <div class="form-group"><label>Faixa/Graduação</label><select id="a-faixa">${faixas.map(f=>`<option${a.faixa===f?' selected':''}>${f}</option>`).join('')}</select></div>
      <div class="form-group"><label>Status</label><select id="a-status">${['Ativo','Inativo','Suspenso'].map(s=>`<option${a.status===s?' selected':''}>${s}</option>`).join('')}</select></div>
      <div class="form-group"><label>Data de Matrícula</label><input type="date" id="a-mat" value="${a.matricula||new Date().toISOString().split('T')[0]}"></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveAluno('${id||''}')">Salvar</button>
    </div>`;
  document.getElementById('a-mod').value=a.modalidade||'Kung-Fu';
  document.getElementById('modal-overlay').classList.add('open');
}

function saveAluno(id){
  const nome=document.getElementById('a-nome').value.trim();
  if(!nome)return alert('Informe o nome do aluno');
  const obj={id:id||uid(),nome,cpf:document.getElementById('a-cpf').value,nascimento:document.getElementById('a-nasc').value,telefone:document.getElementById('a-tel').value,email:document.getElementById('a-email').value,filialId:document.getElementById('a-filial').value,modalidade:document.getElementById('a-mod').value,faixa:document.getElementById('a-faixa').value,status:document.getElementById('a-status').value,matricula:document.getElementById('a-mat').value};
  saveListItem('alunos',id,obj);
  closeModal();renderAlunos();renderDashboard();
}

// ====================== PRESENÇA ======================
function getPresencas(){return Store.get('presencas')||[];}

function initPresenca(){
  // seed presencas se vazio
  if(getPresencas().length===0){seedPresencas();}
  populateTurmaSelect();
  populateTurmaHistSelect();
  populateTurmaFreqSelect();
  // set today
  const d=document.getElementById('pres-data-sel');
  if(d&&!d.value) d.value=new Date().toISOString().split('T')[0];
  renderHistorico();
  renderFrequencia();
}

let activePresTab='pres-chamada';
function switchPresTab(el){
  activePresTab=el.dataset.tab;
  document.querySelectorAll('#sec-presenca .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  ['pres-chamada','pres-historico','pres-freq'].forEach(t=>{
    const elTab=document.getElementById('tab-'+t);
    if(elTab)elTab.style.display=t===activePresTab?'block':'none';
  });
  if(activePresTab==='pres-historico')renderHistorico();
  if(activePresTab==='pres-freq')renderFrequencia();
}

function seedPresencas(){
  const turmas=getTurmas();
  const hoje=new Date();
  const registros=[];
  turmas.forEach(t=>{
    const alunos=t.inscritos||[];
    // gerar presenças dos últimos 30 dias para dias da turma
    for(let i=29;i>=0;i--){
      const d=new Date(hoje);d.setDate(d.getDate()-i);
      const nomeDia=['Domingo','Segunda','Terça','Quarta','Quinta','Sexta','Sábado'][d.getDay()];
      if(!(t.dias||[]).includes(nomeDia))continue;
      const dateStr=d.toISOString().split('T')[0];
      alunos.forEach(aId=>{
        const rand=Math.random();
        const status=rand>0.15?'Presente':rand>0.05?'Ausente':'Justificado';
        registros.push({id:uid(),turmaId:t.id,filialId:t.filialId,alunoId:aId,data:dateStr,status,obs:status==='Justificado'?'Atestado médico':''});
      });
    }
  });
  Store.set('presencas',registros);
}

let chamadaTemp={};// {alunoId: status}

function populateTurmaSelect(){
  const sel=document.getElementById('pres-turma-sel');if(!sel)return;
  const fil=(document.getElementById('pres-fil-chamada')||{}).value||'';
  const cur=sel.value;
  let turmas=getTurmas();
  if(fil)turmas=turmas.filter(t=>t.filialId===fil);
  sel.innerHTML='<option value="">— Selecionar Turma —</option>'+turmas.map(t=>`<option value="${t.id}">${t.nome} (${filialNome(t.filialId)})</option>`).join('');
  sel.value=cur||'';
  loadChamada();
}

function populateTurmaHistSelect(){
  const sel=document.getElementById('pres-hist-turma');if(!sel)return;
  const cur=sel.value;
  sel.innerHTML='<option value="">Todas as Turmas</option>'+getTurmas().map(t=>`<option value="${t.id}">${t.nome}</option>`).join('');
  sel.value=cur||'';
}

function populateTurmaFreqSelect(){
  const sel=document.getElementById('pres-freq-turma');if(!sel)return;
  const cur=sel.value;
  sel.innerHTML='<option value="">Todas as Turmas</option>'+getTurmas().map(t=>`<option value="${t.id}">${t.nome}</option>`).join('');
  sel.value=cur||'';
}

function loadChamada(){
  const turmaId=(document.getElementById('pres-turma-sel')||{}).value||'';
  const data=(document.getElementById('pres-data-sel')||{}).value||'';
  const wrap=document.getElementById('chamada-wrap');if(!wrap)return;
  if(!turmaId||!data){
    wrap.innerHTML=`<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg><p>Selecione uma turma e a data para registrar a chamada</p></div>`;
    return;
  }
  const turma=getTurmas().find(t=>t.id===turmaId);if(!turma)return;
  const alunos=getAlunos().filter(a=>(turma.inscritos||[]).includes(a.id));
  const presencas=getPresencas().filter(p=>p.turmaId===turmaId&&p.data===data);
  chamadaTemp={};
  presencas.forEach(p=>{chamadaTemp[p.alunoId]=p.status;});

  const [y,m,d2]=data.split('-');
  wrap.innerHTML=`
    <div class="report-section">
      <div class="report-title" style="margin-bottom:12px">${turma.nome} — ${d2}/${m}/${y}</div>
      <div style="display:flex;gap:16px;margin-bottom:12px;font-size:13px;font-weight:700">
        <span style="color:var(--green)">&#10003; Presente</span>
        <span style="color:var(--red)">&#10007; Ausente</span>
        <span style="color:var(--amber)">&#9888; Justificado</span>
      </div>
      <div id="chamada-alunos">
        ${alunos.length===0?'<p style="color:var(--gray);font-size:13px">Nenhum aluno inscrito nesta turma</p>':alunos.map(a=>{
          const st=chamadaTemp[a.id]||'';
          return`<div class="pres-aluno-row" id="row-${a.id}">
            <div class="pres-avatar-sm">${a.nome[0]}</div>
            <div style="flex:1">
              <div style="font-weight:700;font-size:14px">${a.nome}</div>
              <div style="font-size:11px;color:var(--gray)">${a.modalidade} — ${a.faixa}</div>
            </div>
            <div style="display:flex;gap:6px">
              <button class="pres-btn presente${st==='Presente'?' sel':''}" onclick="setChamada('${a.id}','Presente')" title="Presente">&#10003;</button>
              <button class="pres-btn ausente${st==='Ausente'?' sel':''}" onclick="setChamada('${a.id}','Ausente')" title="Ausente">&#10007;</button>
              <button class="pres-btn justificado${st==='Justificado'?' sel':''}" onclick="setChamada('${a.id}','Justificado')" title="Justificado">&#9888;</button>
            </div>
          </div>`;
        }).join('')}
      </div>
      <div style="display:flex;gap:16px;margin-top:16px;padding-top:12px;border-top:2px solid var(--light)">
        <div style="font-size:13px;font-weight:700;color:var(--gray)">Total: <strong style="color:var(--dark)">${alunos.length}</strong> alunos</div>
        <button class="btn btn-secondary btn-sm" onclick="marcarTodos('Presente')">Marcar todos Presentes</button>
        <button class="btn btn-danger btn-sm" onclick="marcarTodos('Ausente')">Marcar todos Ausentes</button>
      </div>
    </div>`;
}

function setChamada(alunoId,status){
  chamadaTemp[alunoId]=status;
  const row=document.getElementById('row-'+alunoId);if(!row)return;
  row.querySelectorAll('.pres-btn').forEach(b=>b.classList.remove('sel'));
  const mapa={Presente:'presente',Ausente:'ausente',Justificado:'justificado'};
  const btn=row.querySelector('.pres-btn.'+mapa[status]);
  if(btn)btn.classList.add('sel');
}

function marcarTodos(status){
  const turmaId=(document.getElementById('pres-turma-sel')||{}).value||'';
  const turma=getTurmas().find(t=>t.id===turmaId);if(!turma)return;
  (turma.inscritos||[]).forEach(id=>setChamada(id,status));
}

function salvarChamada(){
  const turmaId=(document.getElementById('pres-turma-sel')||{}).value||'';
  const data=(document.getElementById('pres-data-sel')||{}).value||'';
  if(!turmaId||!data)return alert('Selecione a turma e a data');
  const turma=getTurmas().find(t=>t.id===turmaId);if(!turma)return;
  let presencas=getPresencas().filter(p=>!(p.turmaId===turmaId&&p.data===data));
  (turma.inscritos||[]).forEach(aId=>{
    const st=chamadaTemp[aId];
    if(st)presencas.push({id:uid(),turmaId,filialId:turma.filialId,alunoId:aId,data,status:st,obs:''});
  });
  Store.set('presencas',presencas);
  alert('Chamada salva com sucesso!');
  renderHistorico();
}

function renderHistorico(){
  const q=(document.getElementById('pres-hist-search')||{}).value||'';
  const turmaId=(document.getElementById('pres-hist-turma')||{}).value||'';
  const status=(document.getElementById('pres-hist-status')||{}).value||'';
  const dataFilt=(document.getElementById('pres-hist-data')||{}).value||'';
  let data=getPresencas();
  if(turmaId)data=data.filter(p=>p.turmaId===turmaId);
  if(status)data=data.filter(p=>p.status===status);
  if(dataFilt)data=data.filter(p=>p.data===dataFilt);
  if(q)data=data.filter(p=>alunoNome(p.alunoId).toLowerCase().includes(q.toLowerCase()));
  data=data.slice().sort((a,b)=>b.data.localeCompare(a.data)).slice(0,200);
  const tb=document.getElementById('pres-hist-tbody');if(!tb)return;
  const stBadge={Presente:'badge-green',Ausente:'badge-red',Justificado:'badge-yellow'};
  if(!data.length){tb.innerHTML=`<tr><td colspan="7"><div class="empty-state"><p>Nenhum registro encontrado</p></div></td></tr>`;return;}
  const turmaMap={};getTurmas().forEach(t=>{turmaMap[t.id]=t.nome;});
  tb.innerHTML=data.map(p=>`<tr>
    <td><strong>${alunoNome(p.alunoId)}</strong></td>
    <td>${turmaMap[p.turmaId]||'—'}</td>
    <td>${filialNome(p.filialId)}</td>
    <td>${fmtDate(p.data)}</td>
    <td><span class="badge ${stBadge[p.status]||'badge-gray'}">${p.status}</span></td>
    <td style="font-size:12px;color:var(--gray)">${p.obs||'—'}</td>
    <td><button class="btn btn-danger btn-sm" onclick="deletePresenca('${p.id}')">Excluir</button></td>
  </tr>`).join('');
}

function deletePresenca(id){
  if(!confirm('Excluir este registro?'))return;
  deleteListItem('presencas',id);
  renderHistorico();renderFrequencia();
}

function renderFrequencia(){
  const filFil=(document.getElementById('pres-freq-fil')||{}).value||'';
  const turmaFil=(document.getElementById('pres-freq-turma')||{}).value||'';
  const period=parseInt((document.getElementById('pres-freq-period')||{}).value||'30');
  const gf=getGlobalFilial();
  const wrap=document.getElementById('freq-alunos-wrap');if(!wrap)return;

  const hoje=new Date();
  const limite=new Date(hoje);limite.setDate(hoje.getDate()-period);
  const limStr=limite.toISOString().split('T')[0];

  let alunos=getAlunos().filter(a=>a.status==='Ativo');
  if(gf!=='all')alunos=alunos.filter(a=>a.filialId===gf);
  if(filFil)alunos=alunos.filter(a=>a.filialId===filFil);

  const presencas=getPresencas().filter(p=>p.data>=limStr);
  const turmas=getTurmas();

  const dados=alunos.map(a=>{
    let turmasAluno=turmas.filter(t=>(t.inscritos||[]).includes(a.id));
    if(turmaFil)turmasAluno=turmasAluno.filter(t=>t.id===turmaFil);
    const pAluno=presencas.filter(p=>p.alunoId===a.id&&turmasAluno.some(t=>t.id===p.turmaId));
    const total=pAluno.length;
    const presentes=pAluno.filter(p=>p.status==='Presente').length;
    const ausentes=pAluno.filter(p=>p.status==='Ausente').length;
    const justif=pAluno.filter(p=>p.status==='Justificado').length;
    const pct=total>0?Math.round(presentes/total*100):0;
    // calendário dos últimos 30 dias
    const dias=[];
    for(let i=period-1;i>=0;i--){
      const d=new Date(hoje);d.setDate(d.getDate()-i);
      const ds=d.toISOString().split('T')[0];
      const reg=pAluno.find(p=>p.data===ds);
      dias.push({d:d.getDate(),status:reg?reg.status:(d>hoje?'futuro':'')});
    }
    return{a,total,presentes,ausentes,justif,pct,dias,turmasAluno};
  }).filter(d=>d.total>0||d.turmasAluno.length>0).sort((a,b)=>a.pct-b.pct);

  if(!dados.length){wrap.innerHTML='<div class="empty-state"><p>Nenhum aluno com registros no período</p></div>';return;}

  const cor=pct=>pct>=80?'var(--green)':pct>=60?'var(--amber)':'var(--red)';

  wrap.innerHTML=dados.map(({a,total,presentes,ausentes,justif,pct,dias,turmasAluno})=>`
    <div class="report-section" style="margin-bottom:14px">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px">
        <div class="profile-avatar" style="width:48px;height:48px;font-size:20px">${a.nome[0]}</div>
        <div style="flex:1">
          <div style="font-family:'Bebas Neue',sans-serif;font-size:20px;letter-spacing:1px">${a.nome}</div>
          <div style="font-size:12px;color:var(--gray)">${filialNome(a.filialId)} | ${turmasAluno.map(t=>t.nome).join(', ')||'—'}</div>
        </div>
        <div style="text-align:center">
          <div class="freq-pct" style="color:${cor(pct)}">${pct}%</div>
          <div style="font-size:11px;color:var(--gray);font-weight:700">FREQUÊNCIA</div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;text-align:center;min-width:180px">
          <div><div style="font-family:'Bebas Neue',sans-serif;font-size:22px;color:var(--green)">${presentes}</div><div style="font-size:10px;color:var(--gray);font-weight:700">PRES.</div></div>
          <div><div style="font-family:'Bebas Neue',sans-serif;font-size:22px;color:var(--red)">${ausentes}</div><div style="font-size:10px;color:var(--gray);font-weight:700">AUS.</div></div>
          <div><div style="font-family:'Bebas Neue',sans-serif;font-size:22px;color:var(--amber)">${justif}</div><div style="font-size:10px;color:var(--gray);font-weight:700">JUST.</div></div>
        </div>
      </div>
      <div class="stat-bar-wrap" style="margin-bottom:10px">
        <div class="stat-bar-label"><span>Frequência (${period} dias)</span><span>${presentes}/${total} aulas</span></div>
        <div class="stat-bar-bg" style="height:10px"><div class="stat-bar-fill" style="width:${pct}%;background:linear-gradient(90deg,${cor(pct)},${pct>=80?'var(--yellow)':pct>=60?'var(--orange)':'#F87171'})"></div></div>
      </div>
      <div style="font-size:11px;font-weight:700;color:var(--gray);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px">Histórico (últimos ${period} dias)</div>
      <div class="freq-grid">${dias.map(({d,status})=>`<div class="freq-dia ${status}" title="${status||'Sem aula'}">${d}</div>`).join('')}</div>
    </div>`).join('');
}

// ====================== TURMAS ======================
function getTurmas(){return Store.get('turmas')||[];}
function instrutorNome(id){const i=getInstrutores().find(x=>x.id===id);return i?i.nome:'—';}

const DIAS_SEMANA=['Segunda','Terça','Quarta','Quinta','Sexta','Sábado'];
const MOD_CLASS={'Kung-Fu':'mod-kf','Boxe Chinês':'mod-bc','Thai Chi':'mod-tc'};
const HORARIOS=['05:30','06:00','07:00','08:00','09:00','10:00','11:00','12:00','13:00','14:00','15:00','16:00','17:00','18:00','19:00','20:00','21:00'];

let activeTurmasTab='turmas-lista';
function switchTurmasTab(el){
  activeTurmasTab=el.dataset.tab;
  document.querySelectorAll('#sec-turmas .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  ['turmas-lista','turmas-grade'].forEach(t=>{document.getElementById('tab-'+t).style.display=t===activeTurmasTab?'block':'none';});
  if(activeTurmasTab==='turmas-grade')renderGradeSemanal();
}

function renderTurmas(){
  const q=(document.getElementById('turmas-search')||{}).value||'';
  const fil=(document.getElementById('turmas-fil-filter')||{}).value||'';
  const mod=(document.getElementById('turmas-mod-filter')||{}).value||'';
  const gf=getGlobalFilial();
  let data=getTurmas();
  if(gf!=='all')data=data.filter(t=>t.filialId===gf);
  if(fil)data=data.filter(t=>t.filialId===fil);
  if(mod)data=data.filter(t=>t.modalidade===mod);
  if(q)data=data.filter(t=>t.nome.toLowerCase().includes(q.toLowerCase()));
  const tb=document.getElementById('turmas-tbody');if(!tb)return;
  if(!data.length){tb.innerHTML=`<tr><td colspan="10"><div class="empty-state"><p>Nenhuma turma cadastrada</p></div></td></tr>`;return;}
  tb.innerHTML=data.map(t=>{
    const pct=t.vagas?Math.round((t.inscritos||[]).length/t.vagas*100):0;
    const cls=MOD_CLASS[t.modalidade]||'';
    return`<tr>
      <td><strong>${t.nome}</strong><br><span class="badge badge-gray" style="font-size:10px">${t.nivel}</span></td>
      <td>${filialNome(t.filialId)}</td>
      <td><span class="badge ${cls?'badge-blue':''}" style="${cls?'background:var(--orange);color:#fff':''}">${t.modalidade}</span></td>
      <td>${instrutorNome(t.instrutorId)}</td>
      <td style="font-size:12px">${(t.dias||[]).join(', ')}</td>
      <td><strong>${t.horaInicio}</strong> – ${t.horaFim}</td>
      <td>${t.vagas}</td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <span>${(t.inscritos||[]).length}/${t.vagas}</span>
          <div style="width:50px;height:6px;background:#F3F4F6;border-radius:3px;overflow:hidden">
            <div style="height:100%;width:${pct}%;background:${pct>=90?'var(--red)':pct>=70?'var(--amber)':'var(--green)'}"></div>
          </div>
        </div>
      </td>
      <td>${statusBadge(t.status)}</td>
      <td><button class="btn btn-secondary btn-sm" onclick="openModalTurma('${t.id}')">Editar</button> <button class="btn btn-danger btn-sm" onclick="deleteTurma('${t.id}')">Excluir</button></td>
    </tr>`;
  }).join('');
}

function deleteTurma(id){if(!confirm('Excluir esta turma?'))return;deleteListItem('turmas',id);renderTurmas();renderGradeSemanal();}

function openModalTurma(id){
  const t=id?getTurmas().find(x=>x.id===id):{};
  const filiais=getFiliais();const inst=getInstrutores();
  document.getElementById('modal-title').textContent=id?'EDITAR TURMA':'NOVA TURMA';
  document.getElementById('modal-body').innerHTML=`
    <div class="form-grid">
      <div class="form-group full"><label>Nome da Turma</label><input type="text" id="tu-nome" value="${t.nome||''}"></div>
      <div class="form-group"><label>Associação</label><select id="tu-filial">${filiais.map(f=>`<option value="${f.id}"${t.filialId===f.id?' selected':''}>${f.nome}</option>`).join('')}</select></div>
      <div class="form-group"><label>Modalidade</label><select id="tu-mod"><option>Kung-Fu</option><option>Boxe Chines</option></select></div>
      <div class="form-group"><label>Nível</label><select id="tu-nivel"><option>Iniciante</option><option>Básico</option><option>Intermediário</option><option>Avançado</option></select></div>
      <div class="form-group"><label>Instrutor Responsável</label><select id="tu-inst"><option value="">— Selecionar —</option>${inst.map(i=>`<option value="${i.id}"${t.instrutorId===i.id?' selected':''}>${i.nome}</option>`).join('')}</select></div>
      <div class="form-group"><label>Horário Início</label><input type="time" id="tu-ini" value="${t.horaInicio||'05:30'}"></div>
      <div class="form-group"><label>Horário Fim</label><input type="time" id="tu-fim" value="${t.horaFim||'08:00'}"></div>
      <div class="form-group"><label>Vagas</label><input type="number" id="tu-vagas" value="${t.vagas||35}" min="1"></div>
      <div class="form-group"><label>Status</label><select id="tu-status"><option value="Ativa" ${t.status==='Ativa'?' selected':''}>Ativa</option><option value="Inativa" ${t.status==='Inativa'?' selected':''}>Inativa</option><option value="Encerrada" ${t.status==='Encerrada'?' selected':''}>Encerrada</option></select></div>
      <div class="form-group full"><label>Dias da Semana</label><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px">${DIAS_SEMANA.map(d=>`<label style="display:flex;align-items:center;gap:4px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;color:var(--dark)"><input type="checkbox" class="tu-dia" value="${d}" ${(t.dias||[]).includes(d)?'checked':''}> ${d}</label>`).join('')}</div></div>
      <div class="form-group full"><label>Alunos Inscritos</label><div style="max-height:140px;overflow-y:auto;border:2px solid #E5E7EB;border-radius:8px;padding:8px;display:flex;flex-direction:column;gap:4px">${getAlunos().map(a=>`<label style="display:flex;align-items:center;gap:6px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;color:var(--dark)"><input type="checkbox" class="tu-aluno" value="${a.id}" ${(t.inscritos||[]).includes(a.id)?'checked':''}> ${a.nome} <span style="font-size:11px;color:var(--gray)">(${filialNome(a.filialId)})</span></label>`).join('')}</div></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveTurma('${id||''}')">Salvar</button>
    </div>`;
  document.getElementById('tu-mod').value=t.modalidade||'Kung-Fu';
  document.getElementById('tu-nivel').value=t.nivel||'Iniciante';
  document.getElementById('tu-status').value=t.status||'Ativa';
  document.getElementById('modal-overlay').classList.add('open');
}

function saveTurma(id){
  const nome=document.getElementById('tu-nome').value.trim();
  if(!nome)return alert('Informe o nome da turma');
  
  const dias=getCheckedValues('.tu-dia:checked');
  const inscritos=getCheckedValues('.tu-aluno:checked');
  
  const tuStatusEl = document.getElementById('tu-status');
  const status = tuStatusEl ? tuStatusEl.value : 'Ativa';
  
  const obj={
    id: id ? id : uid(),
    nome,
    filialId:document.getElementById('tu-filial').value,
    modalidade:document.getElementById('tu-mod').value,
    nivel:document.getElementById('tu-nivel').value,
    instrutorId:document.getElementById('tu-inst').value,
    horaInicio:document.getElementById('tu-ini').value,
    horaFim:document.getElementById('tu-fim').value,
    vagas:Number(document.getElementById('tu-vagas').value),
    status:status,
    dias,
    inscritos
  };
  
  console.log('[Turma] Salvando turma:', obj);
  saveListItem('turmas', id ? id : null, obj);
  closeModal();
  renderTurmas();
  renderGradeSemanal();
}

function renderGradeSemanal(){
  const wrap=document.getElementById('grade-semanal-wrap');if(!wrap)return;
  const selFil=(document.getElementById('turmas-grade-filial')||{}).value||'';
  const gf=getGlobalFilial();
  let turmas=getTurmas().filter(t=>t.status==='Ativa');
  if(gf!=='all')turmas=turmas.filter(t=>t.filialId===gf);
  if(selFil)turmas=turmas.filter(t=>t.filialId===selFil);

  let html='<div class="grade-wrap"><div class="grade-grid">';
  // headers
  html+='<div class="grade-col-header time-col">Horário</div>';
  DIAS_SEMANA.forEach(d=>{html+=`<div class="grade-col-header">${d}</div>`;});
  // slots
  HORARIOS.forEach(h=>{
    html+=`<div class="grade-slot time-label">${h}</div>`;
    DIAS_SEMANA.forEach(dia=>{
      const aulas=turmas.filter(t=>(t.dias||[]).includes(dia)&&t.horaInicio===h);
      html+='<div class="grade-slot">';
      aulas.forEach(t=>{
        const cls=MOD_CLASS[t.modalidade]||'';
        html+=`<div class="grade-turma-card ${cls}" onclick="openModalTurma('${t.id}')" title="${t.nome} — ${instrutorNome(t.instrutorId)}">
          <div>${t.nome}</div>
          <div style="opacity:.85;font-weight:600">${t.horaInicio}–${t.horaFim}</div>
          <div style="opacity:.75;font-size:10px">${(t.inscritos||[]).length}/${t.vagas} vagas</div>
        </div>`;
      });
      html+='</div>';
    });
  });
  html+='</div></div>';
  wrap.innerHTML=html;
}

// ====================== INSTRUTORES ======================
function renderInstrutores(){
  const q=(document.getElementById('inst-search')||{}).value||'';
  const fil=(document.getElementById('inst-fil-filter')||{}).value||'';
  const tipo=(document.getElementById('inst-tipo-filter')||{}).value||'';
  const gf=getGlobalFilial();
  const canEdit=isAdmin();
  let data=getInstrutores();
  if(gf!=='all')data=data.filter(i=>(i.filiais||[]).includes(gf));
  if(fil)data=data.filter(i=>(i.filiais||[]).includes(fil));
  if(tipo)data=data.filter(i=>i.tipo===tipo);
  if(q)data=data.filter(i=>i.nome.toLowerCase().includes(q.toLowerCase()));
  const tb=document.getElementById('inst-tbody');if(!tb)return;
  if(!data.length){tb.innerHTML=`<tr><td colspan="8"><div class="empty-state"><p>Nenhum instrutor encontrado</p></div></td></tr>`;return;}
  tb.innerHTML=data.map(i=>`<tr>
    <td><strong>${i.nome}</strong></td>
    <td>${statusBadge(i.tipo)}</td>
    <td>${i.especialidade}</td>
    <td><span class="badge badge-yellow">${i.faixa}</span></td>
    <td>${(i.filiais||[]).map(fid=>`<span class="badge badge-orange" style="margin:1px">${filialNome(fid)}</span>`).join('')}</td>
    <td>${i.cargaHoraria}h/sem</td>
    <td>${statusBadge(i.status)}</td>
    <td>${canEdit?`<button class="btn btn-secondary btn-sm" onclick="openModalInstrutor('${i.id}')">Editar</button> <button class="btn btn-danger btn-sm" onclick="deleteInstrutor('${i.id}')">Excluir</button>`:'<span class="badge badge-gray">Apenas administrador</span>'}</td>
  </tr>`).join('');
}

function deleteInstrutor(id){
  if(!isAdmin())return alert('Apenas administradores podem excluir instrutores');
  if(!confirm('Excluir?'))return;
  deleteListItem('instrutores',id);renderInstrutores();
}

function openModalInstrutor(id){
  if(!isAdmin())return alert('Apenas administradores podem editar ou cadastrar instrutores');
  const inst=id?getInstrutores().find(x=>x.id===id):{};
  const filiais=getFiliais();
  document.getElementById('modal-title').textContent=id?'EDITAR INSTRUTOR':'NOVO INSTRUTOR/PROFESSOR';
  document.getElementById('modal-body').innerHTML=`
    <div class="form-grid">
      <div class="form-group full"><label>Nome Completo</label><input type="text" id="i-nome" value="${inst.nome||''}"></div>
      <div class="form-group"><label>CPF</label><input type="text" id="i-cpf" value="${inst.cpf||''}"></div>
      <div class="form-group"><label>Tipo</label><select id="i-tipo"><option${inst.tipo==='Professor'?' selected':''}>Professor</option><option${inst.tipo==='Instrutor'?' selected':''}>Instrutor</option><option${inst.tipo==='Mestre'?' selected':''}>Mestre</option><option${inst.tipo==='Sifu'?' selected':''}>Sifu</option></select></div>
      <div class="form-group"><label>Especialidade</label><select id="i-esp"><option>Kung-Fu</option><option>Boxe Chines</option><option>Thai Chi</option></select></div>
      <div class="form-group"><label>Faixa/Graduação</label><input type="text" id="i-faixa" value="${inst.faixa||''}"></div>
      <div class="form-group"><label>Carga Horária (h/sem)</label><input type="number" id="i-ch" value="${inst.cargaHoraria||0}"></div>
      <div class="form-group"><label>Salário (R$)</label><input type="number" id="i-sal" value="${inst.salario||0}"></div>
      <div class="form-group"><label>Status</label><select id="i-status"><option${inst.status==='Ativo'?' selected':''}>Ativo</option><option${inst.status==='Inativo'?' selected':''}>Inativo</option></select></div>
      <div class="form-group full"><label>Associações Vinculadas</label><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px">${filiais.map(f=>`<label style="display:flex;align-items:center;gap:4px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;color:var(--dark)"><input type="checkbox" value="${f.id}" ${(inst.filiais||[]).includes(f.id)?'checked':''}> ${f.nome}</label>`).join('')}</div></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveInstrutor('${id||''}')">Salvar</button>
    </div>`;
  document.getElementById('i-esp').value=inst.especialidade||'Kung-Fu';
  document.getElementById('modal-overlay').classList.add('open');
}

function saveInstrutor(id){
  const nome=document.getElementById('i-nome').value.trim();
  if(!nome)return alert('Informe o nome');
  const filialSel=getCheckedValues('#modal-body input[type=checkbox]:checked');
  const obj={id:id||uid(),nome,cpf:document.getElementById('i-cpf').value,tipo:document.getElementById('i-tipo').value,especialidade:document.getElementById('i-esp').value,faixa:document.getElementById('i-faixa').value,filiais:filialSel,cargaHoraria:document.getElementById('i-ch').value,salario:document.getElementById('i-sal').value,status:document.getElementById('i-status').value};
  saveListItem('instrutores',id,obj);
  closeModal();renderInstrutores();
}

// ====================== FINANCEIRO ======================
let activeFinTab='mensalidades';
function switchFinTab(el){
  activeFinTab=el.dataset.tab;
  document.querySelectorAll('#sec-financeiro .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  ['mensalidades','despesas','fluxo'].forEach(t=>{
    document.getElementById('tab-'+t).style.display=t===activeFinTab?'block':'none';
  });
  if(activeFinTab==='fluxo')renderFluxo();
}

function renderMensalidades(){
  const q=(document.getElementById('mens-search')||{}).value||'';
  const fil=(document.getElementById('mens-fil-filter')||{}).value||'';
  const st=(document.getElementById('mens-status-filter')||{}).value||'';
  const gf=getGlobalFilial();
  let data=getMensalidades();
  if(gf!=='all')data=data.filter(m=>m.filialId===gf);
  if(fil)data=data.filter(m=>m.filialId===fil);
  if(st)data=data.filter(m=>m.status===st);
  if(q)data=data.filter(m=>alunoNome(m.alunoId).toLowerCase().includes(q.toLowerCase()));
  const tb=document.getElementById('mens-tbody');if(!tb)return;
  if(!data.length){tb.innerHTML=`<tr><td colspan="8"><div class="empty-state"><p>Nenhum lançamento encontrado</p></div></td></tr>`;return;}
  tb.innerHTML=data.map(m=>`<tr>
    <td><strong>${alunoNome(m.alunoId)}</strong></td>
    <td>${filialNome(m.filialId)}</td>
    <td>${m.referencia}</td>
    <td>${fmtDate(m.vencimento)}</td>
    <td><strong>${fmt(m.valor)}</strong></td>
    <td>${m.metodo}</td>
    <td>${statusBadge(m.status)}</td>
    <td><button class="btn btn-secondary btn-sm" onclick="openModalMensalidade('${m.id}')">Editar</button> <button class="btn btn-danger btn-sm" onclick="deleteMensalidade('${m.id}')">Excluir</button></td>
  </tr>`).join('');
  updateAlertCount();
}

function deleteMensalidade(id){if(!confirm('Excluir?'))return;deleteListItem('mensalidades',id);renderMensalidades();}

function openModalMensalidade(id){
  const m=id?getMensalidades().find(x=>x.id===id):{};
  const alunos=getAlunos();const filiais=getFiliais();
  document.getElementById('modal-title').textContent=id?'EDITAR MENSALIDADE':'LANÇAR MENSALIDADE';
  document.getElementById('modal-body').innerHTML=`
    <div class="form-grid">
      <div class="form-group full"><label>Aluno</label><select id="m-aluno">${alunos.map(a=>`<option value="${a.id}"${m.alunoId===a.id?' selected':''}>${a.nome}</option>`).join('')}</select></div>
      <div class="form-group"><label>Associação</label><select id="m-filial">${filiais.map(f=>`<option value="${f.id}"${m.filialId===f.id?' selected':''}>${f.nome}</option>`).join('')}</select></div>
      <div class="form-group"><label>Referência (AAAA-MM)</label><input type="text" id="m-ref" value="${m.referencia||''}"></div>
      <div class="form-group"><label>Vencimento</label><input type="date" id="m-venc" value="${m.vencimento||''}"></div>
      <div class="form-group"><label>Valor (R$)</label><input type="number" id="m-val" value="${m.valor||150}"></div>
      <div class="form-group"><label>Método</label><select id="m-met"><option${m.metodo==='Pix'?' selected':''}>Pix</option><option${m.metodo==='Cartão'?' selected':''}>Cartão</option><option${m.metodo==='Dinheiro'?' selected':''}>Dinheiro</option><option${m.metodo==='Boleto'?' selected':''}>Boleto</option></select></div>
      <div class="form-group full"><label>Status</label><select id="m-status">${['Pago','Pendente','Em Atraso'].map(s=>`<option${m.status===s?' selected':''}>${s}</option>`).join('')}</select></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveMensalidade('${id||''}')">Salvar</button>
    </div>`;
  document.getElementById('modal-overlay').classList.add('open');
}

function saveMensalidade(id){
  const obj={id:id||uid(),alunoId:document.getElementById('m-aluno').value,filialId:document.getElementById('m-filial').value,referencia:document.getElementById('m-ref').value,vencimento:document.getElementById('m-venc').value,valor:Number(document.getElementById('m-val').value),metodo:document.getElementById('m-met').value,status:document.getElementById('m-status').value};
  saveListItem('mensalidades',id,obj);
  closeModal();renderMensalidades();
}

function renderDespesas(){
  const q=(document.getElementById('desp-search')||{}).value||'';
  const fil=(document.getElementById('desp-fil-filter')||{}).value||'';
  const gf=getGlobalFilial();
  let data=getDespesas();
  if(gf!=='all')data=data.filter(d=>d.filialId===gf);
  if(fil)data=data.filter(d=>d.filialId===fil);
  if(q)data=data.filter(d=>d.descricao.toLowerCase().includes(q.toLowerCase()));
  const tb=document.getElementById('desp-tbody');if(!tb)return;
  if(!data.length){tb.innerHTML=`<tr><td colspan="6"><div class="empty-state"><p>Nenhuma despesa cadastrada</p></div></td></tr>`;return;}
  tb.innerHTML=data.map(d=>`<tr>
    <td><strong>${d.descricao}</strong></td>
    <td>${filialNome(d.filialId)}</td>
    <td><span class="badge badge-orange">${d.categoria}</span></td>
    <td>${fmtDate(d.data)}</td>
    <td><strong style="color:var(--red)">${fmt(d.valor)}</strong></td>
    <td><button class="btn btn-secondary btn-sm" onclick="openModalDespesa('${d.id}')">Editar</button> <button class="btn btn-danger btn-sm" onclick="deleteDespesa('${d.id}')">Excluir</button></td>
  </tr>`).join('');
}

function deleteDespesa(id){if(!confirm('Excluir?'))return;deleteListItem('despesas',id);renderDespesas();}

function openModalDespesa(id){
  const d=id?getDespesas().find(x=>x.id===id):{};
  const filiais=getFiliais();
  document.getElementById('modal-title').textContent=id?'EDITAR DESPESA':'NOVA DESPESA';
  document.getElementById('modal-body').innerHTML=`
    <div class="form-grid">
      <div class="form-group full"><label>Descrição</label><input type="text" id="d-desc" value="${d.descricao||''}"></div>
      <div class="form-group"><label>Associação</label><select id="d-filial">${filiais.map(f=>`<option value="${f.id}"${d.filialId===f.id?' selected':''}>${f.nome}</option>`).join('')}</select></div>
      <div class="form-group"><label>Categoria</label><select id="d-cat"><option${d.categoria==='Aluguel'?' selected':''}>Aluguel</option><option${d.categoria==='Salários'?' selected':''}>Salários</option><option${d.categoria==='Equipamentos'?' selected':''}>Equipamentos</option><option${d.categoria==='Outros'?' selected':''}>Outros</option></select></div>
      <div class="form-group"><label>Data</label><input type="date" id="d-data" value="${d.data||''}"></div>
      <div class="form-group"><label>Valor (R$)</label><input type="number" id="d-val" value="${d.valor||0}"></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveDespesa('${id||''}')">Salvar</button>
    </div>`;
  document.getElementById('modal-overlay').classList.add('open');
}

async function saveDespesa(id){
  const descricao=document.getElementById('d-desc').value.trim();
  const filialId=document.getElementById('d-filial').value;
  const data=document.getElementById('d-data').value;
  const valor=Number(document.getElementById('d-val').value);

  if(!descricao)return alert('Informe a descrição da despesa');
  if(!filialId)return alert('Selecione uma associação');
  if(!data)return alert('Informe a data da despesa');
  if(!Number.isFinite(valor)||valor<=0)return alert('Informe um valor maior que zero');

  const obj={id:id||uid(),descricao,filialId,categoria:document.getElementById('d-cat').value,data,valor};
  const list=getList('despesas');
  if(id){
    const index=list.findIndex(item=>item.id===id);
    if(index>=0)list[index]=obj;else list.push(obj);
  }else{
    list.push(obj);
  }

  try{
    Store.set('despesas',list,{skipRemote:true});
    await Store.saveRemote('despesas',{throwOnError:true});
    closeModal();
    renderDespesas();
  }catch(error){
    console.error('[Despesas] Erro ao salvar:',error);
    alert(`Não foi possível salvar a despesa: ${error.message}`);
  }
}

function renderFluxo(){
  const el=document.getElementById('fluxo-content');if(!el)return;
  const filiais=getFiliais();
  const mens=getMensalidades();
  const desp=getDespesas();
  const gf=getGlobalFilial();
  const fList=gf!=='all'?filiais.filter(f=>f.id===gf):filiais;
  let html='';
  fList.forEach(f=>{
    const rec=mens.filter(m=>m.filialId===f.id&&m.status==='Pago').reduce((s,m)=>s+m.valor,0);
    const despT=desp.filter(d=>d.filialId===f.id).reduce((s,d)=>s+d.valor,0);
    const saldo=rec-despT;
    const pend=mens.filter(m=>m.filialId===f.id&&m.status==='Pendente').reduce((s,m)=>s+m.valor,0);
    const atr=mens.filter(m=>m.filialId===f.id&&m.status==='Em Atraso').reduce((s,m)=>s+m.valor,0);
    html+=`<div class="report-section">
      <div class="report-title">${f.nome}</div>
      <div class="cards-row cards-4" style="margin-bottom:0">
        <div class="card card-green"><div class="card-label">Receita</div><div class="card-value" style="font-size:24px">${fmt(rec)}</div></div>
        <div class="card card-red"><div class="card-label">Despesas</div><div class="card-value" style="font-size:24px">${fmt(despT)}</div></div>
        <div class="card" style="border-top-color:${saldo>=0?'var(--green)':'var(--red)'}"><div class="card-label">Saldo</div><div class="card-value" style="font-size:24px;color:${saldo>=0?'var(--green)':'var(--red)'}">${fmt(saldo)}</div></div>
        <div class="card card-yellow"><div class="card-label">A Receber</div><div class="card-value" style="font-size:24px">${fmt(pend+atr)}</div></div>
      </div>
      <div style="margin-top:16px">
        <div class="stat-bar-wrap"><div class="stat-bar-label"><span>Receita vs Despesa</span><span>${rec>0?Math.round(despT/rec*100):0}% comprometido</span></div><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:${rec>0?Math.min(100,Math.round(despT/rec*100)):0}%;background:linear-gradient(90deg,var(--green),var(--yellow))"></div></div></div>
        <div class="stat-bar-wrap"><div class="stat-bar-label"><span>Inadimplência</span><span>${fmt(atr)}</span></div><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:${rec>0?Math.min(100,Math.round(atr/rec*100)):0}%;background:linear-gradient(90deg,var(--orange),var(--red))"></div></div></div>
      </div>
    </div>`;
  });
  el.innerHTML=html||'<div class="empty-state"><p>Selecione uma associação ou aguarde dados</p></div>';
}

// ====================== EVENTOS ======================
let calYear=new Date().getFullYear(),calMonth=new Date().getMonth();
function changeCalMonth(d){calMonth+=d;if(calMonth>11){calMonth=0;calYear++;}if(calMonth<0){calMonth=11;calYear--;}renderCalendario();}
let activeEvTab='ev-lista';
function switchEvTab(el){
  activeEvTab=el.dataset.tab;
  document.querySelectorAll('#sec-eventos .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  ['ev-lista','ev-calendario'].forEach(t=>{document.getElementById('tab-'+t).style.display=t===activeEvTab?'block':'none';});
  if(activeEvTab==='ev-calendario')renderCalendario();
}

function renderEventos(){
  const q=(document.getElementById('ev-search')||{}).value||'';
  const fil=(document.getElementById('ev-fil-filter')||{}).value||'';
  const gf=getGlobalFilial();
  let data=getEventos();
  if(gf!=='all')data=data.filter(e=>e.filialId===gf);
  if(fil)data=data.filter(e=>e.filialId===fil);
  if(q)data=data.filter(e=>e.nome.toLowerCase().includes(q.toLowerCase()));
  const tb=document.getElementById('ev-tbody');if(!tb)return;
  const tipoBadge={Campeonato:'badge-orange',Seminário:'badge-blue',Graduação:'badge-yellow','Open Day':'badge-green'};
  if(!data.length){tb.innerHTML=`<tr><td colspan="6"><div class="empty-state"><p>Nenhum evento cadastrado</p></div></td></tr>`;return;}
  tb.innerHTML=data.map(e=>`<tr>
    <td><strong>${e.nome}</strong></td>
    <td><span class="badge ${tipoBadge[e.tipo]||'badge-gray'}">${e.tipo}</span></td>
    <td>${filialNome(e.filialId)}</td>
    <td>${fmtDate(e.data)}</td>
    <td>${(e.participantes||[]).length} inscritos</td>
    <td><button class="btn btn-secondary btn-sm" onclick="openModalEvento('${e.id}')">Editar</button> <button class="btn btn-danger btn-sm" onclick="deleteEvento('${e.id}')">Excluir</button></td>
  </tr>`).join('');
}

function deleteEvento(id){if(!confirm('Excluir?'))return;deleteListItem('eventos',id);renderEventos();renderCalendario();}

function openModalEvento(id){
  const ev=id?getEventos().find(x=>x.id===id):{};
  const filiais=getFiliais();const alunos=getAlunos();
  document.getElementById('modal-title').textContent=id?'EDITAR EVENTO':'NOVO EVENTO';
  document.getElementById('modal-body').innerHTML=`
    <div class="form-grid">
      <div class="form-group full"><label>Nome do Evento</label><input type="text" id="e-nome" value="${ev.nome||''}"></div>
      <div class="form-group"><label>Tipo</label><select id="e-tipo"><option value="Campeonato" ${ev.tipo==='Campeonato'?' selected':''}>Campeonato</option><option value="Seminário" ${ev.tipo==='Seminário'?' selected':''}>Seminário</option><option value="Graduação" ${ev.tipo==='Graduação'?' selected':''}>Graduação</option><option value="Open Day" ${ev.tipo==='Open Day'?' selected':''}>Open Day</option></select></div>
      <div class="form-group"><label>Data</label><input type="date" id="e-data" value="${ev.data||''}"></div>
      <div class="form-group"><label>Associação</label><select id="e-filial">${filiais.map(f=>`<option value="${f.id}"${ev.filialId===f.id?' selected':''}>${f.nome}</option>`).join('')}</select></div>
      <div class="form-group full"><label>Descrição</label><textarea id="e-desc">${ev.descricao||''}</textarea></div>
      <div class="form-group full"><label>Participantes</label><div style="max-height:150px;overflow-y:auto;border:2px solid #E5E7EB;border-radius:8px;padding:8px;display:flex;flex-direction:column;gap:4px">${alunos.map(a=>`<label style="display:flex;align-items:center;gap:6px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;color:var(--dark)"><input type="checkbox" class="ev-part" value="${a.id}" ${(ev.participantes||[]).includes(a.id)?'checked':''}> ${a.nome} (${filialNome(a.filialId)})</label>`).join('')}</div></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveEvento('${id||''}')">Salvar</button>
    </div>`;
  document.getElementById('e-tipo').value=ev.tipo||'Campeonato';
  document.getElementById('modal-overlay').classList.add('open');
}

function saveEvento(id){
  const nome=document.getElementById('e-nome').value.trim();
  if(!nome)return alert('Informe o nome do evento');
  
  const parts=getCheckedValues('.ev-part:checked');
  
  const eTipoEl = document.getElementById('e-tipo');
  const tipo = eTipoEl ? eTipoEl.value : 'Campeonato';
  
  const obj={
    id: id ? id : uid(),
    nome,
    tipo:tipo,
    data:document.getElementById('e-data').value,
    filialId:document.getElementById('e-filial').value,
    descricao:document.getElementById('e-desc').value,
    participantes:parts
  };
  
  console.log('[Evento] Salvando evento:', obj);
  saveListItem('eventos', id ? id : null, obj);
  closeModal();
  renderEventos();
  renderCalendario();
}

function renderCalendario(){
  const label=document.getElementById('cal-month-label');
  const wrap=document.getElementById('calendario-wrap');
  if(!label||!wrap)return;
  const months=['Janeiro','Fevereiro','Março','Abril','Maio','Junho','Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];
  label.textContent=`${months[calMonth]} ${calYear}`;
  const eventos=getEventos();
  const first=new Date(calYear,calMonth,1).getDay();
  const days=new Date(calYear,calMonth+1,0).getDate();
  const today=new Date();
  let html='<div class="calendar-grid">';
  ['Dom','Seg','Ter','Qua','Qui','Sex','Sáb'].forEach(d=>{html+=`<div class="cal-header">${d}</div>`;});
  for(let i=0;i<first;i++)html+='<div class="cal-day empty"></div>';
  for(let d=1;d<=days;d++){
    const isToday=d===today.getDate()&&calMonth===today.getMonth()&&calYear===today.getFullYear();
    const dayStr=`${calYear}-${String(calMonth+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    const dayEvs=eventos.filter(e=>e.data===dayStr);
    html+=`<div class="cal-day${isToday?' today':''}"><div class="cal-day-num">${d}</div>${dayEvs.map(e=>`<div class="cal-event" title="${e.nome}">${e.nome}</div>`).join('')}</div>`;
  }
  html+='</div>';
  wrap.innerHTML=html;
}

// ====================== RELATÓRIOS ======================
let activeRelTab='rel-filial';
function switchRelTab(el){
  activeRelTab=el.dataset.tab;
  document.querySelectorAll('#sec-relatorios .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  ['rel-filial','rel-consolid','rel-financeiro','rel-instrutores'].forEach(t=>{document.getElementById('tab-'+t).style.display=t===activeRelTab?'block':'none';});
}

function renderRelatorioFilial(){
  const filiais=getFiliais();const alunos=getAlunos();const mens=getMensalidades();const desp=getDespesas();
  const gf=getGlobalFilial();
  const fList=gf!=='all'?filiais.filter(f=>f.id===gf):filiais;
  document.getElementById('rel-filial-content').innerHTML=fList.map(f=>{
    const fa=alunos.filter(a=>a.filialId===f.id);
    const at=fa.filter(a=>a.status==='Ativo');
    const inAt=fa.filter(a=>a.status==='Inativo');
    const susp=fa.filter(a=>a.status==='Suspenso');
    const rec=mens.filter(m=>m.filialId===f.id&&m.status==='Pago').reduce((s,m)=>s+m.valor,0);
    const despT=desp.filter(d=>d.filialId===f.id).reduce((s,d)=>s+d.valor,0);
    const inadimp=mens.filter(m=>m.filialId===f.id&&m.status==='Em Atraso');
    const pct=fa.length?Math.round(at.length/fa.length*100):0;
    return`<div class="report-section">
      <div class="report-title">Associação: ${f.nome} — ${f.cidade}</div>
      <div style="font-size:12px;color:var(--gray);margin-bottom:12px">Responsável: ${f.responsavel} | Modalidades: ${(f.modalidades||[]).join(', ')}</div>
      <div class="cards-row cards-3" style="margin-bottom:12px">
        <div class="card card-green"><div class="card-label">Alunos Ativos</div><div class="card-value">${at.length}</div><div class="card-sub">${pct}% do total</div></div>
        <div class="card card-red"><div class="card-label">Alunos Inativos</div><div class="card-value">${inAt.length}</div><div class="card-sub">desligados</div></div>
        <div class="card card-yellow"><div class="card-label">Suspensos</div><div class="card-value">${susp.length}</div><div class="card-sub">temporariamente</div></div>
      </div>
      <div class="cards-row cards-3" style="margin-bottom:12px">
        <div class="card card-green"><div class="card-label">Receita</div><div class="card-value" style="font-size:22px">${fmt(rec)}</div></div>
        <div class="card card-red"><div class="card-label">Despesas</div><div class="card-value" style="font-size:22px">${fmt(despT)}</div></div>
        <div class="card card-red"><div class="card-label">Inadimplentes</div><div class="card-value">${inadimp.length}</div><div class="card-sub">${fmt(inadimp.reduce((s,m)=>s+m.valor,0))} em atraso</div></div>
      </div>
      <div class="stat-bar-wrap"><div class="stat-bar-label"><span>Taxa de Retenção</span><span>${pct}%</span></div><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:${pct}%"></div></div></div>
    </div>`;
  }).join('')||'<div class="empty-state"><p>Nenhuma associação encontrada</p></div>';
}

function renderRelatorioConsolidado(){
  const filiais=getFiliais();const alunos=getAlunos();const mens=getMensalidades();const desp=getDespesas();
  const rows=filiais.map(f=>{
    const fa=alunos.filter(a=>a.filialId===f.id);
    const at=fa.filter(a=>a.status==='Ativo').length;
    const rec=mens.filter(m=>m.filialId===f.id&&m.status==='Pago').reduce((s,m)=>s+m.valor,0);
    const despT=desp.filter(d=>d.filialId===f.id).reduce((s,d)=>s+d.valor,0);
    return{...f,total:fa.length,ativos:at,inativos:fa.length-at,receita:rec,despesas:despT,saldo:rec-despT};
  });
  const maxA=Math.max(...rows.map(r=>r.total),1);
  document.getElementById('rel-consolid-content').innerHTML=`
    <div class="report-section">
      <div class="report-title">Comparativo entre Associações</div>
      <div class="table-wrap" style="margin-bottom:20px"><table>
        <thead><tr><th>Associação</th><th>Total Alunos</th><th>Ativos</th><th>Inativos</th><th>Receita</th><th>Despesas</th><th>Saldo</th></tr></thead>
        <tbody>${rows.map(r=>`<tr>
          <td><strong>${r.nome}</strong></td>
          <td>${r.total}</td>
          <td><span class="badge badge-green">${r.ativos}</span></td>
          <td><span class="badge badge-red">${r.inativos}</span></td>
          <td style="color:var(--green);font-weight:700">${fmt(r.receita)}</td>
          <td style="color:var(--red);font-weight:700">${fmt(r.despesas)}</td>
          <td style="color:${r.saldo>=0?'var(--green)':'var(--red)'};font-weight:800">${fmt(r.saldo)}</td>
        </tr>`).join('')}</tbody>
      </table></div>
      <div class="card-label" style="margin-bottom:8px">Alunos por Associação</div>
      ${rows.map(r=>`<div class="stat-bar-wrap"><div class="stat-bar-label"><span>${r.nome}</span><span>${r.total} alunos (${r.ativos} ativos)</span></div><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:${Math.round(r.total/maxA*100)}%"></div></div></div>`).join('')}
    </div>`;
}

function renderRelatorioFinanceiro(){
  const filiais=getFiliais();const mens=getMensalidades();const desp=getDespesas();
  document.getElementById('rel-fin-content').innerHTML=`<div class="report-section">
    <div class="report-title">Fluxo de Caixa Consolidado</div>
    <div class="table-wrap"><table>
      <thead><tr><th>Associação</th><th>Receita (Pago)</th><th>Pendente</th><th>Em Atraso</th><th>Despesas</th><th>Saldo Líquido</th></tr></thead>
      <tbody>${filiais.map(f=>{
        const rec=mens.filter(m=>m.filialId===f.id&&m.status==='Pago').reduce((s,m)=>s+m.valor,0);
        const pend=mens.filter(m=>m.filialId===f.id&&m.status==='Pendente').reduce((s,m)=>s+m.valor,0);
        const atr=mens.filter(m=>m.filialId===f.id&&m.status==='Em Atraso').reduce((s,m)=>s+m.valor,0);
        const despT=desp.filter(d=>d.filialId===f.id).reduce((s,d)=>s+d.valor,0);
        const saldo=rec-despT;
        return`<tr><td><strong>${f.nome}</strong></td><td style="color:var(--green);font-weight:700">${fmt(rec)}</td><td style="color:var(--amber)">${fmt(pend)}</td><td style="color:var(--red)">${fmt(atr)}</td><td style="color:var(--red)">${fmt(despT)}</td><td style="color:${saldo>=0?'var(--green)':'var(--red)'};font-weight:800">${fmt(saldo)}</td></tr>`;
      }).join('')}</tbody>
    </table></div>
  </div>`;
}

function renderRelatorioInstrutores(){
  const filiais=getFiliais();const inst=getInstrutores();
  document.getElementById('rel-inst-content').innerHTML=filiais.map(f=>{
    const fi=inst.filter(i=>(i.filiais||[]).includes(f.id));
    return`<div class="report-section">
      <div class="report-title">Instrutores — ${f.nome}</div>
      ${fi.length?`<div class="table-wrap"><table>
        <thead><tr><th>Nome</th><th>Tipo</th><th>Especialidade</th><th>Faixa</th><th>C.H.</th><th>Salário</th><th>Status</th></tr></thead>
        <tbody>${fi.map(i=>`<tr><td>${i.nome}</td><td>${statusBadge(i.tipo)}</td><td>${i.especialidade}</td><td><span class="badge badge-yellow">${i.faixa}</span></td><td>${i.cargaHoraria}h/sem</td><td>${fmt(i.salario)}</td><td>${statusBadge(i.status)}</td></tr>`).join('')}</tbody>
      </table></div>`:'<p style="color:var(--gray);font-size:13px">Nenhum instrutor vinculado</p>'}
    </div>`;
  }).join('');
}

// ====================== MODAL ======================
function closeModal(){document.getElementById('modal-overlay').classList.remove('open');}
document.getElementById('modal-overlay').addEventListener('click',function(e){if(e.target===this)closeModal();});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();});

// ====================== NAV ITEMS ======================
document.querySelectorAll('.nav-item').forEach(item=>{
  item.addEventListener('click',()=>navigate(item.dataset.route));
});
document.getElementById('filial-global').addEventListener('change',()=>{
  const h=(location.hash||'#dashboard').replace('#','');renderPage(h);
});

// ====================== INIT ======================
async function restoreSession() {
  Store.init();
  authToken = '';
  sessionStorage.removeItem('ap_authToken');
  localStorage.removeItem('ap_loggedUser');
  loggedUser = null;
  if (location.hash !== '#login') location.hash = '#login';
}

async function initApp() {
  try {
    console.log('[INIT] Iniciando aplicação');

    await restoreSession();
    await hydrateFromDB();
    await seedData();

    populateFilialSelects();

    window.addEventListener('hashchange', route);

    renderAuthState();
    await refreshAdminCreationUI();

    console.log('[INIT] Aplicação pronta');
  } catch (error) {
    console.error('[INIT] Erro crítico:', error);
  }
}

initApp();