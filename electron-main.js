const { app, BrowserWindow, net } = require('electron');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const SERVER_URL = `http://localhost:${PORT}`;
const profileName = process.versions.electron.startsWith('22.')
  ? 'AcademiaPro+-Windows7-Experimental'
  : 'AcademiaPro+';
app.setPath('userData', path.join(app.getPath('appData'), profileName, process.arch));

function waitForServer(url, timeout = 10000) {
  return new Promise((resolve) => {
    const start = Date.now();

    function tryConnect() {
      const request = net.request(url);
      request.on('response', () => resolve(true));
      request.on('error', () => {
        if (Date.now() - start > timeout) {
          resolve(false);
        } else {
          setTimeout(tryConnect, 250);
        }
      });
      request.end();
    }

    tryConnect();
  });
}

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1400,
    height: 860,
    minWidth: 1024,
    minHeight: 720,
    icon: path.join(__dirname, 'Imagens', 'icone.ico'),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true
    }
  });

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith(SERVER_URL)) event.preventDefault();
  });

  mainWindow.loadURL(SERVER_URL);

  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }
}

app.whenReady().then(async () => {
  fs.mkdirSync(app.getPath('userData'), { recursive: true });
  process.env.ACADEMIA_DB_PATH = process.env.ACADEMIA_DB_PATH || path.join(app.getPath('userData'), 'academia.sqlite');
  process.env.ACADEMIA_LOG_DIR = process.env.ACADEMIA_LOG_DIR || path.join(app.getPath('userData'), 'logs');
  require('./server.js');

  const serverReady = await waitForServer(SERVER_URL);
  if (!serverReady) {
    console.error(`[Electron] Servidor indisponível em ${SERVER_URL}`);
    app.quit();
    return;
  }
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
