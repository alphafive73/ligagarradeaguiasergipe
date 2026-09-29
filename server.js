const express = require('express');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.ACADEMIA_DB_PATH || path.join(__dirname, 'academia.sqlite');
const LOG_DIR = process.env.ACADEMIA_LOG_DIR || path.join(__dirname, 'logs');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ALLOWED_ROLES = new Set(['Administrador', 'Gestor']);
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

const logger = console;

console.log('[Server] Usando DB_PATH:', DB_PATH);

// Middleware
app.disable('x-powered-by');
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
});
app.use(express.json({ limit: '1mb', strict: true }));
app.use((req, res, next) => {
    if (/\.(sqlite|sqlite3|db|log|env|pem|key|map)(\.|$)/i.test(req.path) ||
        req.path.startsWith('/logs/') ||
        /^\/(server|electron-main|package|package-lock|preload)\.js(on)?$/i.test(req.path) ||
        req.path.startsWith('/.github/') || req.path.startsWith('/release/')) {
        return res.status(404).end();
    }
    next();
});
app.use(express.static(__dirname, { dotfiles: 'deny', index: 'index.html' }));

const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_REQUESTS = 20;

function allowLoginAttempt(key) {
    const now = Date.now();
    const current = loginAttempts.get(key);
    if (!current || now - current.startedAt > LOGIN_WINDOW_MS) {
        loginAttempts.set(key, { startedAt: now, count: 1 });
        return true;
    }
    current.count += 1;
    return current.count <= MAX_LOGIN_REQUESTS;
}

// Configurações
const CONFIG = {
    validTables: ['filiais', 'alunos', 'instrutores', 'mensalidades', 'despesas', 'eventos', 'turmas', 'presencas', 'users'],
    tableJsonFields: {
        filiais: ['modalidades'],
        instrutores: ['filiais'],
        turmas: ['dias', 'inscritos'],
        eventos: ['participantes'],
        users: ['filialIds']
    }
};

let dbConnection;

// ==================== DATABASE ====================

const DB = {
    async init() {
        try {
            const sqlJsDist = path.dirname(require.resolve('sql.js'));
            const SQL = await initSqlJs({ locateFile: file => path.join(sqlJsDist, file) });

            if (fs.existsSync(DB_PATH)) {
                logger.info('[DB] Carregando banco SQLite existente...');
                const filebuffer = fs.readFileSync(DB_PATH);
                dbConnection = new SQL.Database(filebuffer);
            } else {
                logger.info('[DB] Criando novo banco SQLite...');
                dbConnection = new SQL.Database();
            }

            this.createTables();
            this.repairAssociationReferences();
            this.save();
            logger.info('[DB] ✓ Conectado ao SQLite com sucesso');
            return true;
        } catch (error) {
            logger.error('[DB] ✗ Erro na inicialização:', error);
            return false;
        }
    },

    createTables() {
        if (!dbConnection) return;
        
        const queries = [
            `CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                nome TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                passwordHash TEXT NOT NULL,
                role TEXT NOT NULL,
                filialId TEXT,
                filialIds TEXT,
                createdAt TEXT,
                updatedAt TEXT,
                attempts INTEGER DEFAULT 0,
                lockedUntil TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS filiais (
                id TEXT PRIMARY KEY,
                nome TEXT NOT NULL,
                endereco TEXT,
                cidade TEXT,
                responsavel TEXT,
                modalidades TEXT,
                status TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS alunos (
                id TEXT PRIMARY KEY,
                nome TEXT NOT NULL,
                cpf TEXT,
                nascimento TEXT,
                telefone TEXT,
                email TEXT,
                filialId TEXT,
                modalidade TEXT,
                faixa TEXT,
                status TEXT,
                matricula TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS instrutores (
                id TEXT PRIMARY KEY,
                nome TEXT NOT NULL,
                cpf TEXT,
                tipo TEXT,
                especialidade TEXT,
                faixa TEXT,
                filiais TEXT,
                cargaHoraria INTEGER,
                salario REAL,
                status TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS mensalidades (
                id TEXT PRIMARY KEY,
                alunoId TEXT,
                filialId TEXT,
                referencia TEXT,
                vencimento TEXT,
                dataPagamento TEXT,
                valor REAL,
                metodo TEXT,
                status TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS despesas (
                id TEXT PRIMARY KEY,
                descricao TEXT,
                valor REAL,
                data TEXT,
                categoria TEXT,
                filialId TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS eventos (
                id TEXT PRIMARY KEY,
                nome TEXT,
                tipo TEXT,
                descricao TEXT,
                data TEXT,
                horario TEXT,
                filialId TEXT,
                participantes TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS turmas (
                id TEXT PRIMARY KEY,
                nome TEXT,
                modalidade TEXT,
                instrutorId TEXT,
                filialId TEXT,
                horaInicio TEXT,
                horaFim TEXT,
                dias TEXT,
                vagas INTEGER,
                inscritos TEXT,
                nivel TEXT,
                status TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS presencas (
                id TEXT PRIMARY KEY,
                turmaId TEXT,
                alunoId TEXT,
                data TEXT,
                status TEXT,
                obs TEXT
            )`
        ];

        for (const query of queries) {
            try {
                dbConnection.run(query);
            } catch (error) {
                console.warn('[DB] Tabela já existe ou erro:', error.message);
            }
        }

        try {
            dbConnection.run('ALTER TABLE presencas ADD COLUMN filialId TEXT');
        } catch (error) {
            // A coluna já existe em bancos criados após a migração.
        }
        try {
            dbConnection.run('ALTER TABLE users ADD COLUMN filialId TEXT');
        } catch (error) {
            // A coluna já existe em bancos criados após a migração.
        }
        try {
            dbConnection.run('ALTER TABLE users ADD COLUMN filialIds TEXT');
        } catch (error) {
            // A coluna já existe em bancos criados após a migração.
        }
        // Mantém os usuários legados (uma filial) compatíveis com o novo formato.
        this.fetchAll("SELECT id, filialId FROM users WHERE filialId IS NOT NULL AND (filialIds IS NULL OR filialIds = '')")
            .forEach((user) => dbConnection.run(
                'UPDATE users SET filialIds = ? WHERE id = ?',
                [JSON.stringify([user.filialId]), user.id]
            ));
    },

    repairAssociationReferences() {
        const associations = this.fetchAll('SELECT id, modalidades FROM filiais');
        if (!associations.length) return;

        const validIds = new Set(associations.map((association) => association.id));
        const defaultAssociation = associations[0].id;
        const associationForModality = new Map();

        associations.forEach((association) => {
            let modalities = [];
            try { modalities = JSON.parse(association.modalidades || '[]'); } catch (error) {}
            modalities.forEach((modality) => {
                const matches = associations.filter((item) => {
                    try { return JSON.parse(item.modalidades || '[]').includes(modality); } catch (error) { return false; }
                });
                if (matches.length === 1) associationForModality.set(modality, association.id);
            });
        });

        ['alunos', 'mensalidades', 'despesas', 'eventos', 'turmas', 'presencas'].forEach((table) => {
            const rows = this.fetchAll(`SELECT id, filialId${table === 'alunos' ? ', modalidade' : ''} FROM ${table}`);
            rows.forEach((row) => {
                if (validIds.has(row.filialId)) return;
                const replacement = associationForModality.get(row.modalidade) || defaultAssociation;
                dbConnection.run(`UPDATE ${table} SET filialId = ? WHERE id = ?`, [replacement, row.id]);
            });
        });

        this.fetchAll('SELECT id, filiais FROM instrutores').forEach((row) => {
            let ids = [];
            try { ids = JSON.parse(row.filiais || '[]'); } catch (error) {}
            const valid = ids.filter((id) => validIds.has(id));
            const replacement = valid.length ? valid : [defaultAssociation];
            if (JSON.stringify(ids) !== JSON.stringify(replacement)) {
                dbConnection.run('UPDATE instrutores SET filiais = ? WHERE id = ?', [JSON.stringify(replacement), row.id]);
            }
        });

        this.save();
    },

    save() {
        if (!dbConnection || !DB_PATH) return;
        try {
            const data = dbConnection.export();
            fs.writeFileSync(DB_PATH, Buffer.from(data));
            logger.info('[DB] Banco salvo com sucesso');
        } catch (error) {
            logger.error('[DB] Erro ao salvar banco:', error);
        }
    },

    fetchAll(sql, params = []) {
        try {
            if (!dbConnection) return [];
            // Usa a ligação nativa de parâmetros do sql.js (mesmo mecanismo já usado
            // em dbConnection.run) em vez de montar a query com substituição manual de
            // "?" por texto escapado. A versão anterior usava processedSql.replace(/\?/, ...)
            // sem a flag "g", substituindo um "?" por vez: se qualquer parâmetro (nome,
            // email, descrição etc.) contivesse o caractere "?", a próxima substituição
            // acabava batendo nesse "?" dentro do valor recém-inserido em vez do
            // próximo placeholder real, corrompendo o SQL (ex.: login com um email como
            // "usuario?teste@x.com" gerava uma consulta inválida).
            const result = dbConnection.exec(sql, params);
            if (!result || !result[0]) return [];
            const { columns, values } = result[0];
            return values.map((row) => Object.fromEntries(row.map((value, index) => [columns[index], value])));
        } catch (error) {
            logger.warn('[DB] Erro ao executar SQL:', error.message);
            return [];
        }
    },

    fetchOne(sql, params = []) {
        const rows = this.fetchAll(sql, params);
        return rows.length > 0 ? rows[0] : null;
    },

    getTableColumns(table) {
        try {
            if (!dbConnection) return [];
            const result = dbConnection.exec(`PRAGMA table_info(${table})`);
            if (!result || !result[0]) return [];
            return result[0].values.map((row) => row[1]);
        } catch (error) {
            logger.warn('[DB] Erro ao obter colunas da tabela:', error.message);
            return [];
        }
    },

    getTableInfo(table) {
        try {
            if (!dbConnection) return [];
            const result = dbConnection.exec(`PRAGMA table_info(${table})`);
            if (!result || !result[0]) return [];
            return result[0].values.map((row) => ({
                cid: row[0],
                name: row[1],
                type: row[2],
                notnull: row[3],
                dflt_value: row[4],
                pk: row[5]
            }));
        } catch (error) {
            logger.warn('[DB] Erro ao obter informações da tabela:', error.message);
            return [];
        }
    },

    saveTableSQLite(table, data, options = {}) {
        if (!dbConnection) return;

        let validRows = [];
        let columns = [];

        if (data.length > 0) {
            const tableInfo = this.getTableInfo(table);
            const tableColumns = tableInfo.map((column) => column.name);
            const requiredColumns = tableInfo
                .filter((column) => column.notnull === 1 && column.dflt_value === null)
                .map((column) => column.name);

            validRows = data.filter((row) => {
                return requiredColumns.every((col) => row[col] !== undefined && row[col] !== null);
            });

            if (validRows.length === 0) {
                throw new Error('Nenhuma linha válida para inserir nesta tabela. Campos obrigatórios ausentes.');
            }

            if (validRows.length < data.length) {
                logger.warn(`[DB] Ignorando ${data.length - validRows.length} linha(s) inválida(s) ao salvar tabela ${table}`);
            }

            columns = Object.keys(validRows[0]).filter((col) => tableColumns.includes(col));
            if (columns.length === 0) {
                throw new Error('Nenhuma coluna válida para inserir nesta tabela');
            }
        }

        dbConnection.run(`DELETE FROM ${table}`);

        if (validRows.length > 0) {
            const placeholders = columns.map(() => '?').join(',');

            for (const row of validRows) {
                const values = columns.map((col) => {
                    const value = row[col];
                    if (CONFIG.tableJsonFields[table]?.includes(col) && typeof value === 'object') {
                        return JSON.stringify(value);
                    }
                    return value ?? null;
                });

                dbConnection.run(
                    `INSERT INTO ${table} (${columns.join(',')}) VALUES (${placeholders})`,
                    values
                );
            }
        }

        if (options.persist !== false) this.save();
    },

    saveAllSQLite(data) {
        if (!dbConnection) return;

        dbConnection.run('BEGIN');
        try {
            for (const [table, records] of Object.entries(data)) {
                if (Array.isArray(records) && CONFIG.validTables.includes(table)) {
                    this.saveTableSQLite(table, records, { persist: false });
                }
            }
            dbConnection.run('COMMIT');
            this.save();
        } catch (error) {
            try { dbConnection.run('ROLLBACK'); } catch (rollbackError) {}
            throw error;
        }
    },

    parseRowJsonFields(table, row) {
        const jsonFields = CONFIG.tableJsonFields[table] || [];
        jsonFields.forEach((field) => {
            if (row[field] && typeof row[field] === 'string') {
                try {
                    row[field] = JSON.parse(row[field]);
                } catch (error) {
                    // preserve raw value if parsing fails
                }
            }
        });
        return row;
    }
};

function userBranchIds(user) {
    if (user.role === 'Administrador') {
        return DB.fetchAll('SELECT id FROM filiais').map((row) => row.id);
    }

    let ids = [];
    try {
        ids = Array.isArray(user.filialIds)
            ? user.filialIds
            : JSON.parse(user.filialIds || '[]');
    } catch (error) {}
    if (!Array.isArray(ids) || ids.length === 0) {
        ids = user.filialId ? [user.filialId] : [];
    }
    return [...new Set(ids.filter((id) => typeof id === 'string' && id))];
}

// JWT Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Token de acesso necessário' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Token inválido' });
        }
        // Recarrega o usuário no banco para que role/filial revogados ou alterados
        // tenham efeito imediatamente, sem depender de dados antigos do JWT.
        const currentUser = DB.fetchOne(
            'SELECT id, nome, email, role, filialId, filialIds FROM users WHERE id = ?',
            [user.id]
        );
        if (!currentUser || !ALLOWED_ROLES.has(currentUser.role)) {
            return res.status(403).json({ success: false, error: 'Usuário sem acesso' });
        }
        req.user = {
            ...currentUser,
            filialIds: userBranchIds(currentUser)
        };
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user?.role !== 'Administrador') {
        return res.status(403).json({ success: false, error: 'Acesso restrito a administradores' });
    }
    next();
};

// ==================== API ROUTES ====================

const SERVER_VERSION = {
    name: 'AcademiaPro+',
    env: process.env.NODE_ENV || 'development',
    startedAt: new Date().toISOString(),
    serverFile: 'server.js'
};

app.get('/api/version', (req, res) => {
    try {
        res.json({
            success: true,
            version: SERVER_VERSION,
            database: 'sqlite'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Authentication
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Email e senha são obrigatórios' });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const attemptKey = `${req.ip}:${normalizedEmail}`;
        if (!allowLoginAttempt(attemptKey)) {
            return res.status(429).json({ success: false, error: 'Muitas tentativas. Aguarde alguns minutos.' });
        }

        if (!dbConnection) {
            return res.status(500).json({ success: false, error: 'Banco de dados indisponível' });
        }

        logger.info('[LOGIN] Tentativa de login:', { email: normalizedEmail });

        const user = DB.fetchOne(
            'SELECT id, nome, email, passwordHash, role, filialId, filialIds, attempts, lockedUntil FROM users WHERE lower(email) = ?',
            [normalizedEmail]
        );

        if (!user) {
            return res.status(401).json({ success: false, error: 'Email ou senha incorretos' });
        }

        const { id, nome, email: userEmail, passwordHash, role, filialId, attempts, lockedUntil } = user;
        const filialIds = userBranchIds(user);

        // Check lockout
        if (lockedUntil) {
            const lockTime = new Date(lockedUntil);
            if (lockTime > new Date()) {
                return res.status(401).json({ success: false, error: 'Conta bloqueada. Tente novamente mais tarde.' });
            }
        }

        // Verify password
        const passwordMatch = await bcrypt.compare(password, passwordHash);

        if (!passwordMatch) {
            const newAttempts = (attempts || 0) + 1;
            const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;

            if (newAttempts >= maxAttempts) {
                const lockoutTime = new Date(Date.now() + (parseInt(process.env.LOCKOUT_TIME) || 900000));
                dbConnection.run(
                    'UPDATE users SET attempts = ?, lockedUntil = ? WHERE id = ?',
                    [newAttempts, lockoutTime.toISOString(), id]
                );
                DB.save();
                return res.status(401).json({ success: false, error: 'Muitas tentativas. Conta bloqueada por 15 minutos.' });
            }

            dbConnection.run(
                'UPDATE users SET attempts = ? WHERE id = ?',
                [newAttempts, id]
            );
            DB.save();

            return res.status(401).json({ success: false, error: 'Email ou senha incorretos' });
        }

        // Clear attempts
        dbConnection.run(
            'UPDATE users SET attempts = 0, lockedUntil = NULL WHERE id = ?',
            [id]
        );
        DB.save();

        // Generate JWT
        const token = jwt.sign(
            { id, nome, email: userEmail, role },
            JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        logger.info(`[Auth] ✓ Login bem-sucedido para ${normalizedEmail}`);
        res.json({
            success: true,
            user: { id, nome, email: userEmail, role, filialId: filialId || null, filialIds },
            token
        });
    } catch (error) {
        logger.error('[Auth] ✗ Erro:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/auth/admin-status', async (req, res) => {
    try {
        if (!dbConnection) {
            return res.status(500).json({ exists: false, error: 'Banco de dados indisponível' });
        }

        const admin = DB.fetchOne('SELECT id FROM users WHERE role = ?', ['Administrador']);
        const users = DB.fetchOne('SELECT COUNT(*) AS count FROM users');
        res.json({ exists: !!admin, setupRequired: users?.count === 0 });
    } catch (error) {
        logger.error('[Auth] Erro ao verificar administrador:', error);
        res.status(500).json({ exists: false, error: error.message });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, currentPassword, newPassword } = req.body;

        if (!email || !currentPassword || !newPassword) {
            return res.status(400).json({ success: false, error: 'Email, senha atual e nova senha são obrigatórios' });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const attemptKey = `${req.ip}:reset:${normalizedEmail}`;
        if (!allowLoginAttempt(attemptKey)) {
            return res.status(429).json({ success: false, error: 'Muitas tentativas. Aguarde alguns minutos.' });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
            return res.status(400).json({ success: false, error: 'Email inválido' });
        }

        if (!PASSWORD_REGEX.test(newPassword)) {
            return res.status(400).json({ success: false, error: 'A nova senha deve ter pelo menos 8 caracteres, incluindo maiúsculas, minúsculas, números e símbolos' });
        }

        if (!dbConnection) {
            return res.status(500).json({ success: false, error: 'Banco de dados indisponível' });
        }

        const user = DB.fetchOne(
            'SELECT id, nome, email, passwordHash FROM users WHERE lower(email) = ?',
            [normalizedEmail]
        );

        if (!user) {
            return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
        }

        const passwordMatch = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, error: 'Senha atual incorreta' });
        }

        const newHash = await bcrypt.hash(newPassword, 10);
        const now = new Date().toISOString();

        dbConnection.run(
            'UPDATE users SET passwordHash = ?, attempts = 0, lockedUntil = NULL, updatedAt = ? WHERE id = ?',
            [newHash, now, user.id]
        );
        DB.save();

        res.json({ success: true, message: 'Senha redefinida com sucesso' });
    } catch (error) {
        logger.error('[Auth] Erro ao redefinir senha:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/auth/create-admin', async (req, res) => {
    try {
        const { nome, email, password } = req.body;

        if (!nome || !email || !password) {
            return res.status(400).json({ success: false, error: 'Nome, email e senha são obrigatórios' });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        if (!allowLoginAttempt(`${req.ip}:create-admin`)) {
            return res.status(429).json({ success: false, error: 'Muitas tentativas. Aguarde alguns minutos.' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
            return res.status(400).json({ success: false, error: 'Email inválido' });
        }

        if (!PASSWORD_REGEX.test(password)) {
            return res.status(400).json({ success: false, error: 'Senha fraca: use 8 caracteres, maiúscula, minúscula, número e símbolo' });
        }

        if (!dbConnection) {
            return res.status(500).json({ success: false, error: 'Banco de dados indisponível' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const existingUsers = DB.fetchOne('SELECT COUNT(*) AS count FROM users');
        if (existingUsers?.count !== 0) {
            return res.status(400).json({ success: false, error: 'A configuração inicial já foi concluída' });
        }

        const now = new Date().toISOString();
        const userId = process.env.ADMIN_ID || 'u_admin';

        dbConnection.run(
            `INSERT INTO users (id, nome, email, passwordHash, role, createdAt, updatedAt, attempts, lockedUntil)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)`,
            [userId, nome.trim(), normalizedEmail, passwordHash, 'Administrador', now, now]
        );
        DB.save();

        logger.info(`[Auth] ✓ Administrador criado: ${normalizedEmail}`);
        res.json({ success: true, user: { id: userId, nome: nome.trim(), email: normalizedEmail, role: 'Administrador' } });
    } catch (error) {
        logger.error('[Auth] Erro ao criar administrador:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Database operations
const BRANCH_TABLES = new Set([
    'filiais', 'alunos', 'instrutores', 'mensalidades',
    'despesas', 'eventos', 'turmas', 'presencas'
]);

function belongsToBranch(table, row, filialIds) {
    const allowedIds = filialIds instanceof Set ? filialIds : new Set(filialIds || []);
    if (table === 'filiais') return allowedIds.has(row.id);
    if (table === 'alunos' || table === 'mensalidades' ||
        table === 'despesas' || table === 'eventos' || table === 'turmas' ||
        table === 'presencas') {
        return allowedIds.has(row.filialId);
    }
    if (table === 'instrutores') {
        let branches = [];
        try { branches = typeof row.filiais === 'string' ? JSON.parse(row.filiais || '[]') : row.filiais; } catch (error) {}
        return Array.isArray(branches) && branches.some((id) => allowedIds.has(id));
    }
    return false;
}

function scopeRowsForUser(table, rows, user) {
    if (user.role === 'Administrador' || !BRANCH_TABLES.has(table)) return rows;
    const filialIds = userBranchIds(user);
    if (!filialIds.length) return [];
    return rows.filter(row => belongsToBranch(table, row, filialIds));
}

function mergeScopedRows(table, submittedRows, user) {
    if (user.role === 'Administrador' || !BRANCH_TABLES.has(table)) return submittedRows;
    const filialIds = userBranchIds(user);
    if (!filialIds.length) throw new Error('Usuário gestor sem filial associada');
    const allowedIds = new Set(filialIds);

    const invalid = submittedRows.some(row => !belongsToBranch(table, row, allowedIds));
    if (invalid) {
        const error = new Error('Dados fora das associações vinculadas');
        error.status = 403;
        throw error;
    }

    const existing = DB.fetchAll(`SELECT * FROM ${table}`);
    const untouched = existing.filter(row => !belongsToBranch(table, row, allowedIds));
    return untouched.concat(submittedRows);
}

app.get('/api/db/load', authenticateToken, async (req, res) => {
    try {
        if (!dbConnection) {
            return res.status(500).json({ error: 'Banco de dados indisponível' });
        }

        const result = {};
        for (const table of CONFIG.validTables) {
            try {
                if (table === 'users' && req.user?.role !== 'Administrador') {
                    result[table] = [];
                    continue;
                }

                const query = table === 'users'
                    ? 'SELECT id, nome, email, role, filialId, filialIds, createdAt, updatedAt FROM users'
                    : `SELECT * FROM ${table}`;
                const rows = scopeRowsForUser(table, DB.fetchAll(query), req.user);
                result[table] = rows.map((row) => DB.parseRowJsonFields(table, row));
            } catch (error) {
                logger.warn(`[DB] Erro ao carregar ${table}:`, error.message);
                result[table] = [];
            }
        }

        res.json(result);
    } catch (error) {
        logger.error('[DB] Erro ao carregar dados:', error);
        res.status(error.status || 500).json({ error: error.message });
    }
});

app.post('/api/db/save-table', authenticateToken, async (req, res) => {
    try {
        const { table, data } = req.body;

        if (table === 'filiais' && req.user?.role !== 'Administrador') {
            return res.status(403).json({ success: false, error: 'Apenas administradores podem gerenciar associações' });
        }

        if (table === 'users' && req.user?.role !== 'Administrador') {
            return res.status(403).json({ success: false, error: 'Acesso restrito a administradores' });
        }

        if (!CONFIG.validTables.includes(table)) {
            return res.status(400).json({ error: 'Tabela inválida' });
        }

        if (!dbConnection) {
            return res.status(500).json({ error: 'Banco de dados indisponível' });
        }

        if (!Array.isArray(data)) {
            return res.status(400).json({ error: 'Dados devem ser um array' });
        }

        dbConnection.run('BEGIN');
        try {
            DB.saveTableSQLite(table, mergeScopedRows(table, data, req.user), { persist: false });
            dbConnection.run('COMMIT');
            DB.save();
        } catch (error) {
            try { dbConnection.run('ROLLBACK'); } catch (rollbackError) {}
            throw error;
        }

        res.json({ success: true });
    } catch (error) {
        logger.error('[DB] Erro ao salvar tabela:', error);
        res.status(error.status || 500).json({ error: error.message });
    }
});

app.post('/api/db/save-all', authenticateToken, async (req, res) => {
    try {
        const data = req.body;

        if (Array.isArray(data?.users) && req.user?.role !== 'Administrador') {
            return res.status(403).json({ success: false, error: 'Acesso restrito a administradores' });
        }

        if (Array.isArray(data?.filiais) && req.user?.role !== 'Administrador') {
            return res.status(403).json({ success: false, error: 'Apenas administradores podem gerenciar associações' });
        }

        if (!dbConnection) {
            return res.status(500).json({ error: 'Banco de dados indisponível' });
        }

        const dataToSave = { ...data };
        if (req.user.role !== 'Administrador') {
            for (const table of BRANCH_TABLES) {
                if (Array.isArray(dataToSave[table])) {
                    dataToSave[table] = mergeScopedRows(table, dataToSave[table], req.user);
                }
            }
        }
        DB.saveAllSQLite(dataToSave);

        res.json({ success: true });
    } catch (error) {
        logger.error('[DB] Erro ao salvar tudo:', error);
        res.status(error.status || 500).json({ error: error.message });
    }
});

app.post('/api/db/clear-all', authenticateToken, requireAdmin, (req, res) => {
    try {
        if (!dbConnection) {
            return res.status(500).json({ error: 'Banco de dados indisponível' });
        }

        for (const table of CONFIG.validTables) {
            dbConnection.run(`DELETE FROM ${table}`);
        }

        DB.save();
        res.json({ success: true });
    } catch (error) {
        console.error('[DB] Erro ao limpar banco:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== USER MANAGEMENT ====================

function requestedBranchIds(body, role) {
    if (role !== 'Gestor') return [];
    const submitted = body.filialIds === undefined
        ? (body.filialId ? [body.filialId] : [])
        : body.filialIds;
    if (!Array.isArray(submitted) || submitted.some((id) => typeof id !== 'string' || !id.trim())) {
        return null;
    }
    const ids = [...new Set(submitted.map((id) => id.trim()))];
    if (!ids.length || ids.some((id) => !DB.fetchOne('SELECT id FROM filiais WHERE id = ?', [id]))) {
        return null;
    }
    return ids;
}

// Create new user with password hashing
app.post('/api/users/create', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { nome, email, password, role } = req.body;

        if (!nome || !email || !password || !role) {
            return res.status(400).json({ success: false, error: 'Nome, email, senha e role são obrigatórios' });
        }

        if (!ALLOWED_ROLES.has(role)) {
            return res.status(400).json({ success: false, error: 'Nível de acesso inválido' });
        }
        const filialIds = requestedBranchIds(req.body, role);
        if (filialIds === null) {
            return res.status(400).json({ success: false, error: 'Associe o gestor a uma ou mais associações válidas' });
        }

        if (!PASSWORD_REGEX.test(password)) {
            return res.status(400).json({ success: false, error: 'Senha fraca: use 8 caracteres, maiúscula, minúscula, número e símbolo' });
        }

        if (!dbConnection) {
            return res.status(500).json({ success: false, error: 'Banco de dados indisponível' });
        }

        // Check if email already exists
        const existingUser = DB.fetchOne('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
        if (existingUser) {
            return res.status(400).json({ success: false, error: 'Email já cadastrado' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);
        const now = new Date().toISOString();
        const userId = `u_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Insert user
        dbConnection.run(
            `INSERT INTO users (id, nome, email, passwordHash, role, filialId, filialIds, createdAt, updatedAt, attempts, lockedUntil)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)`,
            [userId, nome, email.toLowerCase(), passwordHash, role, filialIds[0] || null, JSON.stringify(filialIds), now, now]
        );

        DB.save();
        console.log(`[Users] ✓ Usuário criado: ${nome} (${email})`);
        res.json({ success: true, user: { id: userId, nome, email, role, filialId: filialIds[0] || null, filialIds } });
    } catch (error) {
        console.error('[Users] Erro ao criar usuário:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update user (admin only, with optional password change)
app.put('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { nome, email, password, role } = req.body;

        if (!nome || !email || !role) {
            return res.status(400).json({ success: false, error: 'Nome, email e role são obrigatórios' });
        }

        if (!ALLOWED_ROLES.has(role)) {
            return res.status(400).json({ success: false, error: 'Nível de acesso inválido' });
        }
        const filialIds = requestedBranchIds(req.body, role);
        if (filialIds === null) {
            return res.status(400).json({ success: false, error: 'Associe o gestor a uma ou mais associações válidas' });
        }

        if (password && !PASSWORD_REGEX.test(password)) {
            return res.status(400).json({ success: false, error: 'Senha fraca: use 8 caracteres, maiúscula, minúscula, número e símbolo' });
        }

        if (!dbConnection) {
            return res.status(500).json({ success: false, error: 'Banco de dados indisponível' });
        }

        // Check if email already exists for another user
        const existingUser = DB.fetchOne('SELECT id FROM users WHERE email = ? AND id != ?', [email.toLowerCase(), id]);
        if (existingUser) {
            return res.status(400).json({ success: false, error: 'Email já cadastrado por outro usuário' });
        }

        const now = new Date().toISOString();
        let query, params;

        if (password) {
            // Update with new password
            const passwordHash = await bcrypt.hash(password, 10);
            query = 'UPDATE users SET nome = ?, email = ?, passwordHash = ?, role = ?, filialId = ?, filialIds = ?, updatedAt = ? WHERE id = ?';
            params = [nome, email.toLowerCase(), passwordHash, role, filialIds[0] || null, JSON.stringify(filialIds), now, id];
        } else {
            // Update without password change
            query = 'UPDATE users SET nome = ?, email = ?, role = ?, filialId = ?, filialIds = ?, updatedAt = ? WHERE id = ?';
            params = [nome, email.toLowerCase(), role, filialIds[0] || null, JSON.stringify(filialIds), now, id];
        }

        const result = dbConnection.run(query, params);

        if (result.changes === 0) {
            return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
        }

        DB.save();
        console.log(`[Users] ✓ Usuário atualizado: ${nome} (${email})`);
        res.json({ success: true });
    } catch (error) {
        console.error('[Users] Erro ao atualizar usuário:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
    try {
        const { id } = req.params;

        if (id === req.user.id) {
            return res.status(400).json({ success: false, error: 'Não é possível excluir o usuário atualmente conectado' });
        }

        if (!dbConnection) {
            return res.status(500).json({ success: false, error: 'Banco de dados indisponível' });
        }

        // Don't allow deleting the last admin
        const adminCount = DB.fetchOne('SELECT COUNT(*) as count FROM users WHERE role = ?', ['Administrador']);
        const userRole = DB.fetchOne('SELECT role FROM users WHERE id = ?', [id]);

        if (adminCount && adminCount.count <= 1 &&
            userRole && userRole.role === 'Administrador') {
            return res.status(400).json({ success: false, error: 'Não é possível excluir o último administrador' });
        }

        const result = dbConnection.run('DELETE FROM users WHERE id = ?', [id]);

        if (result.changes === 0) {
            return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
        }

        DB.save();
        console.log(`[Users] ✓ Usuário excluído: ${id}`);
        res.json({ success: true });
    } catch (error) {
        console.error('[Users] Erro ao excluir usuário:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    try {
        const dbStatus = dbConnection ? 'connected' : 'disconnected';
        const uptime = process.uptime();
        const memoryUsage = process.memoryUsage();

        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: `${Math.floor(uptime)}s`,
            database: dbStatus,
            memory: {
                rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
                heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
                heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`
            },
            version: '1.0.0'
        });
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// ==================== SERVER STARTUP ====================
async function startServer() {
    try {
        if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
            throw new Error('JWT_SECRET deve ser configurado em produção');
        }

        // Create logs directory
        if (!fs.existsSync(LOG_DIR)) {
            fs.mkdirSync(LOG_DIR, { recursive: true });
        }

        const dbInitialized = await DB.init();
        if (!dbInitialized) {
            logger.error('[Server] Falha ao inicializar banco de dados');
            process.exit(1);
        }

        const server = app.listen(PORT, '127.0.0.1', () => {
            logger.info(`[Server] ✓ AcademiaPro+ rodando em http://localhost:${PORT}`);
            logger.info(`[Server] Acesse: http://localhost:${PORT}`);
        });

        // Graceful shutdown
        process.on('SIGTERM', () => {
            logger.info('[Server] SIGTERM received, shutting down gracefully');
            server.close(() => {
                logger.info('[Server] Process terminated');
            });
        });

        process.on('SIGINT', () => {
            logger.info('[Server] SIGINT received, shutting down gracefully');
            server.close(() => {
                logger.info('[Server] Process terminated');
            });
        });

    } catch (error) {
        logger.error('[Server] ✗ Erro ao iniciar:', error);
        process.exit(1);
    }
}

startServer();

module.exports = app;
