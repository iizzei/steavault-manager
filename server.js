/**
 * SteamVault Manager — Servidor con autenticación Steam OpenID
 * Sin dependencias externas (solo Node.js nativo)
 */
const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');

const PORT = 8000;
const REALM = 'http://localhost:8000';
const RETURN_TO = 'http://localhost:8000/auth/steam/callback';
const STEAM_OPENID_URL = 'https://steamcommunity.com/openid/login';

// Almacenamiento de sesiones en memoria
const sessions = new Map();

// MIME types
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function verifySteamOpenID(params) {
  return new Promise((resolve, reject) => {
    const verifyParams = { ...params, 'openid.mode': 'check_authentication' };
    const postData = new URLSearchParams(verifyParams).toString();

    const req = https.request(STEAM_OPENID_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData),
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (data.includes('is_valid:true')) {
          const claimedId = params['openid.claimed_id'] || '';
          const match = claimedId.match(/https:\/\/steamcommunity\.com\/openid\/id\/(\d+)/);
          resolve(match ? match[1] : null);
        } else {
          resolve(null);
        }
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

function getSteamProfile(steamId) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'steamcommunity.com',
      path: `/profiles/${steamId}?xml=1`,
      headers: { 'User-Agent': 'SteamVault/1.0' },
    };

    https.get(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const nameMatch = data.match(/<steamID><!\[CDATA\[(.*?)\]\]><\/steamID>/);
        const avatarMatch = data.match(/<avatarMedium><!\[CDATA\[(.*?)\]\]><\/avatarMedium>/);
        resolve({
          steam_id: steamId,
          name: nameMatch ? nameMatch[1] : `Usuario ${steamId}`,
          avatar: avatarMatch ? avatarMatch[1] : '',
        });
      });
    }).on('error', () => {
      resolve({ steam_id: steamId, name: 'Usuario Steam', avatar: '' });
    });
  });
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [key, ...val] = cookie.trim().split('=');
      cookies[key] = val.join('=');
    });
  }
  return cookies;
}

function serveStatic(req, res, filePath) {
  const fs = require('fs');
  const path = require('path');

  const safePath = path.join(__dirname, filePath);
  if (!safePath.startsWith(__dirname)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(safePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }
    const ext = path.extname(safePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const path = parsedUrl.pathname;
  const query = parsedUrl.query;

  console.log(`[${new Date().toISOString()}] ${req.method} ${path}`);

  // Iniciar autenticación Steam
  if (path === '/auth/steam') {
    const params = {
      'openid.ns': 'http://specs.openid.net/auth/2.0',
      'openid.mode': 'checkid_setup',
      'openid.return_to': RETURN_TO,
      'openid.realm': REALM,
      'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
      'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select',
    };
    const authUrl = `${STEAM_OPENID_URL}?${new URLSearchParams(params)}`;
    res.writeHead(302, { Location: authUrl });
    res.end();
    return;
  }

  // Callback de Steam
  if (path === '/auth/steam/callback') {
    try {
      const steamId = await verifySteamOpenID(query);
      if (steamId) {
        const profile = await getSteamProfile(steamId);
        const sessionId = `sv_${steamId}_${crypto.randomBytes(4).toString('hex')}`;
        sessions.set(sessionId, profile);

        res.writeHead(302, {
          Location: '/?login=success',
          'Set-Cookie': `sv_session=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`,
        });
        res.end();
      } else {
        res.writeHead(302, { Location: '/?login=error' });
        res.end();
      }
    } catch (err) {
      console.error('Error en callback:', err);
      res.writeHead(302, { Location: '/?login=error' });
      res.end();
    }
    return;
  }

  // Cerrar sesión
  if (path === '/auth/logout') {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.sv_session) {
      sessions.delete(cookies.sv_session);
    }
    res.writeHead(302, {
      Location: '/',
      'Set-Cookie': 'sv_session=; Path=/; HttpOnly; Max-Age=0',
    });
    res.end();
    return;
  }

  // API: usuario actual
  if (path === '/api/me') {
    const cookies = parseCookies(req.headers.cookie);
    const session = cookies.sv_session ? sessions.get(cookies.sv_session) : null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ authenticated: !!session, user: session }));
    return;
  }

  // Archivos estáticos
  let filePath = path === '/' ? '/index.html' : path;
  serveStatic(req, res, filePath);
});

server.listen(PORT, 'localhost', () => {
  console.log(`\n  SteamVault Manager`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  Realm: ${REALM}`);
  console.log(`\n  Presiona Ctrl+C para detener\n`);
});
