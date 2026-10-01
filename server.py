"""
SteamVault Manager — Servidor con autenticación Steam OpenID
"""
import http.server
import urllib.parse
import urllib.request
import json
import re
import ssl
from http.cookies import SimpleCookie

# Configuración
PORT = 8000
REALM = "http://localhost:8000"
RETURN_TO = "http://localhost:8000/auth/steam/callback"
STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"

# Almacenamiento de sesiones (en producción usar Redis/DB)
sessions = {}


def verify_steam_openid(params):
    """Verifica la respuesta OpenID con Steam y extrae el SteamID."""
    verify_params = dict(params)
    verify_params['openid.mode'] = 'check_authentication'

    data = urllib.parse.urlencode(verify_params).encode('utf-8')
    req = urllib.request.Request(STEAM_OPENID_URL, data=data)

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            result = resp.read().decode('utf-8')
            if 'is_valid:true' in result:
                claimed_id = params.get('openid.claimed_id', '')
                match = re.search(r'https://steamcommunity\.com/openid/id/(\d+)', claimed_id)
                if match:
                    return match.group(1)
    except Exception as e:
        print(f"Error verificando OpenID: {e}")
    return None


def get_steam_profile(steam_id):
    """Obtiene el perfil público de Steam (sin API key, usando perfil público)."""
    # Sin API key no podemos usar la Web API. Usamos el perfil público de Steam.
    url = f"https://steamcommunity.com/profiles/{steam_id}?xml=1"
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SteamVault/1.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            xml = resp.read().decode('utf-8')
            # Extraer datos básicos del XML
            name_match = re.search(r'<steamID><!\[CDATA\[(.*?)\]\]></steamID>', xml)
            avatar_match = re.search(r'<avatarMedium><!\[CDATA\[(.*?)\]\]></avatarMedium>', xml)
            return {
                'steam_id': steam_id,
                'name': name_match.group(1) if name_match else f'Usuario {steam_id}',
                'avatar': avatar_match.group(1) if avatar_match else '',
            }
    except Exception as e:
        print(f"Error obteniendo perfil: {e}")
        return {
            'steam_id': steam_id,
            'name': f'Usuario Steam',
            'avatar': '',
        }


class SteamVaultHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Endpoint: Iniciar autenticación Steam
        if path == '/auth/steam':
            self.handle_steam_auth()

        # Endpoint: Callback de Steam
        elif path == '/auth/steam/callback':
            self.handle_steam_callback(query)

        # Endpoint: Cerrar sesión
        elif path == '/auth/logout':
            self.handle_logout()

        # Endpoint: API usuario actual
        elif path == '/api/me':
            self.handle_api_me()

        # Archivos estáticos
        else:
            super().do_GET()

    def handle_steam_auth(self):
        """Redirige al usuario a Steam OpenID."""
        params = {
            'openid.ns': 'http://specs.openid.net/auth/2.0',
            'openid.mode': 'checkid_setup',
            'openid.return_to': RETURN_TO,
            'openid.realm': REALM,
            'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select',
        }
        auth_url = f"{STEAM_OPENID_URL}?{urllib.parse.urlencode(params)}"
        self.send_response(302)
        self.send_header('Location', auth_url)
        self.end_headers()

    def handle_steam_callback(self, query):
        """Procesa la respuesta de Steam OpenID."""
        # Convertir lista a valores simples
        params = {k: v[0] for k, v in query.items()}

        steam_id = verify_steam_openid(params)

        if steam_id:
            profile = get_steam_profile(steam_id)

            # Crear sesión
            session_id = f"sv_{steam_id}_{hash(steam_id) % 10000}"
            sessions[session_id] = profile

            # Redirigir con sesión iniciada
            self.send_response(302)
            self.send_header('Location', '/?login=success')
            self.send_header('Set-Cookie', f'sv_session={session_id}; Path=/; HttpOnly; SameSite=Lax')
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header('Location', '/?login=error')
            self.end_headers()

    def handle_logout(self):
        """Cierra la sesión del usuario."""
        cookie = self.headers.get('Cookie', '')
        if 'sv_session=' in cookie:
            session_id = cookie.split('sv_session=')[1].split(';')[0]
            sessions.pop(session_id, None)

        self.send_response(302)
        self.send_header('Location', '/')
        self.send_header('Set-Cookie', 'sv_session=; Path=/; HttpOnly; Max-Age=0')
        self.end_headers()

    def handle_api_me(self):
        """Devuelve los datos del usuario autenticado."""
        cookie = self.headers.get('Cookie', '')
        session_id = None
        if 'sv_session=' in cookie:
            session_id = cookie.split('sv_session=')[1].split(';')[0]

        user = sessions.get(session_id) if session_id else None

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'authenticated': bool(user), 'user': user}).encode())

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {args[0]}")


if __name__ == '__main__':
    server = http.server.HTTPServer(('localhost', PORT), SteamVaultHandler)
    print(f"SteamVault Manager corriendo en http://localhost:{PORT}")
    print(f"Realm: {REALM}")
    print("Presiona Ctrl+C para detener")
    server.serve_forever()
