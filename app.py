"""
Panel de clientes + back office + chat de demos + dispatcher MCP — Inhumario
============================================================================

- Panel en /: alta, login, credenciales de Odoo, URL MCP propia, chat de demos.
- Back office en /admin (solo ADMIN_EMAIL): alta/baja/borrado de tenants y uso.
- MCP por tenant en /t/<token>/mcp; ruta legacy (MCP_PATH + ODOO_*) intacta.
- Credenciales sensibles (API keys) cifradas en reposo con Fernet (ENCRYPT_KEY).
- Chat de demos: usa la clave API de Claude del tenant contra su propio Odoo.

Variables de entorno:
  SECRET_KEY    — firma de cookies de sesión (obligatoria)
  ENCRYPT_KEY   — clave Fernet para cifrado en reposo (obligatoria)
  ALTA_CODIGO   — código de invitación para el alta
  ADMIN_EMAIL   — email con acceso al back office
  DB_PATH       — sqlite, por defecto /data/tenants.db
  BASE_URL      — URL pública, por defecto https://mcp.inhumario.com
  MCP_PATH, ODOO_URL, ODOO_DB, ODOO_USER, ODOO_API_KEY — tenant legacy (opcional)
"""

import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time

import anthropic
from cryptography.fernet import Fernet
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

import server as srv
from server import mcp, current_tenant, probar_conexion

SECRET_KEY = os.environ["SECRET_KEY"]
ENCRYPT_KEY = os.environ["ENCRYPT_KEY"]
ALTA_CODIGO = os.environ.get("ALTA_CODIGO", "")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()
DB_PATH = os.environ.get("DB_PATH", "/data/tenants.db")
BASE_URL = os.environ.get("BASE_URL", "https://mcp.inhumario.com")

fernet = Fernet(ENCRYPT_KEY.encode())

LEGACY_PATH = os.environ.get("MCP_PATH", "").strip("/")
LEGACY_TENANT = None
if LEGACY_PATH and os.environ.get("ODOO_URL"):
    LEGACY_TENANT = {
        "id": 0,
        "odoo_url": os.environ["ODOO_URL"],
        "odoo_db": os.environ["ODOO_DB"],
        "odoo_user": os.environ["ODOO_USER"],
        "odoo_key": os.environ["ODOO_API_KEY"],
        "instrucciones": os.environ.get("MCP_INSTRUCCIONES", ""),
    }

# ---------------------------------------------------------------- cifrado

def enc(value: str) -> str:
    if not value:
        return ""
    return "enc:" + fernet.encrypt(value.encode()).decode()


def dec(value: str) -> str:
    if not value:
        return ""
    if value.startswith("enc:"):
        return fernet.decrypt(value[4:].encode()).decode()
    return value  # valor antiguo sin cifrar (se migra al arrancar)


# ---------------------------------------------------------------- base de datos

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                empresa TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                pass_hash TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                odoo_url TEXT DEFAULT '',
                odoo_db TEXT DEFAULT '',
                odoo_user TEXT DEFAULT '',
                odoo_key TEXT DEFAULT '',
                ai_claude TEXT DEFAULT '',
                ai_otras TEXT DEFAULT '',
                last_test TEXT DEFAULT '',
                created TEXT DEFAULT (datetime('now'))
            )
        """)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(tenants)")]
        if "activo" not in cols:
            conn.execute("ALTER TABLE tenants ADD COLUMN activo INTEGER DEFAULT 1")
        if "instrucciones" not in cols:
            conn.execute("ALTER TABLE tenants ADD COLUMN instrucciones TEXT DEFAULT ''")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER,
                modelo TEXT,
                metodo TEXT,
                fecha TEXT DEFAULT (datetime('now'))
            )
        """)
    # Migración: cifrar claves que sigan en claro
    with db() as conn:
        for r in conn.execute("SELECT id, odoo_key, ai_claude, ai_otras FROM tenants").fetchall():
            cambios = {}
            for campo in ("odoo_key", "ai_claude", "ai_otras"):
                v = r[campo]
                if v and not v.startswith("enc:"):
                    cambios[campo] = enc(v)
            if cambios:
                sets = ", ".join(f"{c}=?" for c in cambios)
                conn.execute(f"UPDATE tenants SET {sets} WHERE id=?", (*cambios.values(), r["id"]))


def tenant_by(field: str, value) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(f"SELECT * FROM tenants WHERE {field} = ?", (value,)).fetchone()


def log_uso(tenant_id, modelo, metodo) -> None:
    try:
        with db() as conn:
            conn.execute("INSERT INTO usos (tenant_id, modelo, metodo) VALUES (?,?,?)",
                         (tenant_id or 0, str(modelo)[:80], str(metodo)[:80]))
    except Exception:
        pass


srv.USAGE_LOGGER = log_uso


# ---------------------------------------------------------------- auth helpers

_login_fails: dict[str, list] = {}  # email -> [n_fallos, bloqueado_hasta]


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return f"{salt}${h.hex()}"


def check_password(password: str, stored: str) -> bool:
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


def make_session(email: str) -> str:
    exp = str(int(time.time()) + 30 * 86400)
    payload = f"{email}|{exp}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def read_session(request: Request) -> sqlite3.Row | None:
    cookie = request.cookies.get("sesion", "")
    parts = cookie.split("|")
    if len(parts) != 3:
        return None
    email, exp, sig = parts
    expected = hmac.new(SECRET_KEY.encode(), f"{email}|{exp}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected) or int(exp) < time.time():
        return None
    return tenant_by("email", email)


def es_admin(row) -> bool:
    return bool(row) and ADMIN_EMAIL and row["email"] == ADMIN_EMAIL


def new_token() -> str:
    return "mcp-" + secrets.token_hex(24)


# ---------------------------------------------------------------- dispatcher MCP

mcp_app = mcp.http_app(path="/mcp", stateless_http=True)


async def _plain_response(send, status: int, text: str) -> None:
    body = text.encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
    await send({"type": "http.response.body", "body": body})


def tenant_dict(row) -> dict:
    return {"id": row["id"], "odoo_url": row["odoo_url"], "odoo_db": row["odoo_db"],
            "odoo_user": row["odoo_user"], "odoo_key": dec(row["odoo_key"]),
            "instrucciones": row["instrucciones"] or ""}


class RootDispatcher:
    """Capa ASGI más externa: /t/<token>/... va al MCP con el tenant de la BD,
    la ruta legacy va al MCP con el tenant del entorno, y el resto al panel."""

    def __init__(self, panel, mcp_asgi):
        self.panel = panel
        self.mcp_asgi = mcp_asgi

    async def _delegate_mcp(self, tenant: dict, scope, receive, send):
        ctx = current_tenant.set(tenant)
        try:
            scope = dict(scope)
            scope["path"] = "/mcp"
            scope["root_path"] = ""
            await self.mcp_asgi(scope, receive, send)
        finally:
            current_tenant.reset(ctx)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.panel(scope, receive, send)
        path = scope.get("path", "")
        if path.startswith("/t/"):
            parts = path.split("/")
            token = parts[2] if len(parts) > 2 else ""
            row = tenant_by("token", token) if token else None
            if row is None or not row["odoo_url"] or not row["activo"]:
                return await _plain_response(send, 404, "Tenant no encontrado, desactivado o sin credenciales de Odoo")
            return await self._delegate_mcp(tenant_dict(row), scope, receive, send)
        if LEGACY_TENANT and path.rstrip("/") == "/" + LEGACY_PATH:
            return await self._delegate_mcp(LEGACY_TENANT, scope, receive, send)
        return await self.panel(scope, receive, send)


# ---------------------------------------------------------------- FastAPI

panel_app = FastAPI(lifespan=mcp_app.lifespan)
panel_app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")))
init_db()
app = RootDispatcher(panel_app, mcp_app)


# ---------------------------------------------------------------- HTML

CSS = """
:root { --ink:#111111; --ink-soft:#1F1F1F; --mute:#666666; --light:#B5B5B5;
        --card:#F7F7F7; --line:#E5E5E5; --acento:#FF8080;
        --verde-osc:#111111; --verde:#111111; --verde-cl:#B5B5B5;
        --fondo:#F7F7F7; --cabecera:#F7F7F7; --borde:#E5E5E5; --texto:#111111; }
* { box-sizing:border-box; margin:0; }
body { font-family:Calibri,'Helvetica Neue',Arial,sans-serif; background:#FFFFFF;
       color:var(--ink); line-height:1.55; }
header { background:var(--ink); color:#fff; padding:14px 22px; display:flex;
         justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; }
header .logo img { height:26px; display:block; }
header nav { display:flex; gap:18px; }
header a { color:#fff; text-decoration:none; font-size:.9rem; letter-spacing:.02em; }
header a:hover { color:var(--acento); }
main { max-width:900px; margin:26px auto; padding:0 16px 48px; }
.card { background:#fff; border:1px solid var(--line); border-radius:12px;
        padding:24px; margin-bottom:20px; }
.card h2 { color:var(--ink); font-size:1.08rem; margin-bottom:12px;
           border-bottom:2px solid var(--ink); padding-bottom:7px; letter-spacing:.01em; }
.card h3 { color:var(--ink) !important; }
label { display:block; font-size:.85rem; font-weight:600; margin:10px 0 4px; color:var(--ink-soft); }
input, textarea { width:100%; padding:10px; border:1px solid var(--line); border-radius:8px;
        font-size:.95rem; font-family:inherit; background:#fff; }
input:focus, textarea:focus { outline:2px solid var(--ink); border-color:var(--ink); }
textarea { min-height:220px; resize:vertical; line-height:1.5; }
button { background:var(--ink); color:#fff; border:0; border-radius:8px;
         padding:11px 22px; font-size:.95rem; font-weight:600; cursor:pointer;
         margin-top:14px; font-family:inherit; }
button:hover { background:var(--ink-soft); }
.btn-rojo { background:var(--acento); color:var(--ink); } .btn-rojo:hover { background:#ff9a9a; }
.btn-mini { padding:6px 12px; font-size:.8rem; margin:2px; }
.aviso-ok { background:var(--card); border:1px solid var(--ink); color:var(--ink);
            padding:10px 14px; border-radius:8px; margin-bottom:14px; font-size:.9rem; }
.aviso-err { background:#FFF1F0; border:1px solid var(--acento); color:#A03030;
             padding:10px 14px; border-radius:8px; margin-bottom:14px; font-size:.9rem; }
.url-mcp { background:var(--card); border:1px dashed var(--light); border-radius:8px;
           padding:12px; font-family:ui-monospace,monospace; font-size:.8rem;
           word-break:break-all; margin:8px 0; }
.pasos li { margin-bottom:8px; }
a { color:var(--ink); } main a:hover { color:var(--acento); }
.nota { font-size:.82rem; color:var(--mute); margin-top:6px; }
.fila { display:flex; gap:14px; flex-wrap:wrap; }
.fila > div { flex:1; min-width:220px; }
table { width:100%; border-collapse:collapse; font-size:.85rem; }
.tabla-scroll { overflow-x:auto; }
th { background:var(--card); color:var(--ink); text-align:left; padding:8px; }
td { padding:8px; border-bottom:1px solid var(--line); }
tr:nth-child(even) td { background:var(--card); }
#chat-caja { border:1px solid var(--line); border-radius:10px; height:420px; overflow-y:auto;
             padding:14px; background:var(--card); margin-bottom:10px; }
.msg { max-width:85%; padding:10px 14px; border-radius:12px; margin-bottom:10px;
       white-space:pre-wrap; font-size:.92rem; }
.msg-u { background:var(--ink); color:#fff; margin-left:auto; }
.msg-a { background:#fff; border:1px solid var(--line); }
.msg-s { background:#EFEFEF; color:var(--mute); font-size:.8rem; font-style:italic; }
#chat-form { display:flex; gap:8px; }
#chat-form input { flex:1; } #chat-form button { margin-top:0; }
@media (max-width:600px){ .card{padding:16px} main{margin-top:14px} .msg{max-width:95%}
                          header .logo img{height:22px} }
"""


def page(title: str, body: str, logged: bool = False, admin: bool = False) -> HTMLResponse:
    nav = ""
    if logged:
        links = ['<a href="/panel">Panel</a>', '<a href="/chat">Chat de pruebas</a>']
        if admin:
            links.append('<a href="/admin">Administración</a>')
        links.append('<a href="/salir">Salir</a>')
        nav = "<nav>" + "".join(links) + "</nav>"
    return HTMLResponse(f"""<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Inhumario</title>
<link rel="icon" type="image/png" href="/static/icon-square.png">
<style>{CSS}</style></head><body>
<header><a class="logo" href="/panel"><img src="/static/logo-white.png" alt="Inhumario"></a>{nav}</header>
<main>{body}</main></body></html>""")


def e(value) -> str:
    return html.escape(str(value or ""))


# ---------------------------------------------------------------- rutas panel

@panel_app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if read_session(request):
        return RedirectResponse("/panel", status_code=302)
    return RedirectResponse("/login", status_code=302)


@panel_app.get("/salud")
def salud():
    return {"ok": True}


@panel_app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str = ""):
    err = f'<div class="aviso-err">{e(error)}</div>' if error else ""
    return page("Acceso", f"""
<div class="card"><h2>Accede a tu panel</h2>{err}
<form method="post" action="/login">
<label>Email</label><input type="email" name="email" required>
<label>Contraseña</label><input type="password" name="password" required>
<button>Entrar</button></form>
<p class="nota">¿Aún no tienes cuenta? <a href="/alta">Date de alta</a> con tu código de invitación.</p>
</div>""")


@panel_app.post("/login")
def login(email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    fails = _login_fails.get(email, [0, 0])
    if fails[1] > time.time():
        return RedirectResponse("/login?error=Demasiados intentos, espera un minuto", status_code=302)
    row = tenant_by("email", email)
    if not row or not check_password(password, row["pass_hash"]):
        fails[0] += 1
        if fails[0] >= 5:
            fails = [0, time.time() + 60]
        _login_fails[email] = fails
        return RedirectResponse("/login?error=Email o contraseña incorrectos", status_code=302)
    _login_fails.pop(email, None)
    resp = RedirectResponse("/panel", status_code=302)
    resp.set_cookie("sesion", make_session(row["email"]), httponly=True, secure=True,
                    samesite="lax", max_age=30 * 86400)
    return resp


@panel_app.get("/alta", response_class=HTMLResponse)
def alta_form(request: Request, error: str = ""):
    err = f'<div class="aviso-err">{e(error)}</div>' if error else ""
    return page("Alta", f"""
<div class="card"><h2>Crea tu cuenta</h2>{err}
<form method="post" action="/alta">
<div class="fila"><div><label>Empresa</label><input name="empresa" required></div>
<div><label>Email</label><input type="email" name="email" required></div></div>
<div class="fila"><div><label>Contraseña</label><input type="password" name="password" minlength="8" required></div>
<div><label>Código de invitación</label><input name="codigo" required></div></div>
<button>Crear cuenta</button></form>
<p class="nota">¿Ya tienes cuenta? <a href="/login">Entra aquí</a>.</p>
</div>""")


@panel_app.post("/alta")
def alta(empresa: str = Form(...), email: str = Form(...), password: str = Form(...), codigo: str = Form(...)):
    if not ALTA_CODIGO or codigo.strip() != ALTA_CODIGO:
        return RedirectResponse("/alta?error=Código de invitación no válido", status_code=302)
    email = email.strip().lower()
    if tenant_by("email", email):
        return RedirectResponse("/alta?error=Ya existe una cuenta con ese email", status_code=302)
    with db() as conn:
        conn.execute(
            "INSERT INTO tenants (empresa, email, pass_hash, token) VALUES (?,?,?,?)",
            (empresa.strip(), email, hash_password(password), new_token()),
        )
    resp = RedirectResponse("/panel", status_code=302)
    resp.set_cookie("sesion", make_session(email), httponly=True, secure=True,
                    samesite="lax", max_age=30 * 86400)
    return resp


@panel_app.get("/salir")
def salir():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("sesion")
    return resp


@panel_app.get("/panel", response_class=HTMLResponse)
def panel(request: Request, ok: str = "", error: str = ""):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    msg = ""
    if ok:
        msg = f'<div class="aviso-ok">{e(ok)}</div>'
    if error:
        msg = f'<div class="aviso-err">{e(error)}</div>'

    url_mcp = f"{BASE_URL}/t/{row['token']}/mcp"
    estado = (f'<div class="aviso-ok">✅ Conectado a Odoo — {e(row["last_test"])}</div>'
              if row["last_test"] else
              '<div class="aviso-err">⚠️ Aún sin conexión verificada con Odoo. Guarda tus credenciales abajo.</div>')

    conexion = "" if not row["last_test"] else f"""
<div class="card"><h2>2 · Conecta tu IA</h2>
<p>Esta es tu dirección privada de conexión (trátala como una contraseña):</p>
<div class="url-mcp" id="urlmcp">{e(url_mcp)}</div>
<button type="button" onclick="navigator.clipboard.writeText(document.getElementById('urlmcp').innerText).then(()=>this.innerText='¡Copiada!')">Copiar dirección</button>
<h3 style="margin-top:18px;color:var(--verde)">Claude (web y móvil)</h3>
<ol class="pasos">
<li>Entra en <b>claude.ai → Ajustes → Conectores → Añadir conector personalizado</b>.</li>
<li>Nombre: <b>Mi Odoo</b> · URL: pega tu dirección privada → <b>Añadir</b> y <b>Conectar</b>.</li>
<li>En el móvil aparecerá automáticamente en el menú ➕ de herramientas del chat.</li>
</ol>
<h3 style="margin-top:12px;color:var(--verde)">ChatGPT</h3>
<ol class="pasos">
<li>Ajustes → <b>Aplicaciones y conectores</b> → activa el <b>modo desarrollador</b> (Avanzado).</li>
<li><b>Crear conector</b> → pega tu dirección privada → autenticación: «Sin autenticación».</li>
</ol>
<h3 style="margin-top:12px;color:var(--verde)">Otras IAs</h3>
<p class="nota">Cualquier aplicación compatible con el estándar MCP (Copilot Studio, Cursor,
LibreChat, etc.) puede usar la misma dirección. Tipo de servidor: «Streamable HTTP», sin autenticación.</p>
<p class="nota">¿Sin suscripción de IA? Prueba tu Odoo desde el <a href="/chat">chat de pruebas</a>
guardando abajo una clave API de Claude.</p>
<form method="post" action="/panel/regenerar" onsubmit="return confirm('Si regeneras la dirección, la actual dejará de funcionar y tendrás que reconectar tus IAs. ¿Continuar?')">
<button class="btn-rojo">Regenerar dirección (si se ha filtrado)</button></form>
</div>"""

    return page("Panel", f"""
{msg}{estado}
<div class="card"><h2>1 · Tu Odoo</h2>
<form method="post" action="/panel/odoo">
<div class="fila">
<div><label>URL de Odoo</label><input name="odoo_url" placeholder="https://miempresa.odoo.com" value="{e(row['odoo_url'])}" required></div>
<div><label>Base de datos</label><input name="odoo_db" placeholder="miempresa-master-123456" value="{e(row['odoo_db'])}" required></div>
</div>
<div class="fila">
<div><label>Usuario (email)</label><input name="odoo_user" value="{e(row['odoo_user'])}" required></div>
<div><label>API key de Odoo</label><input type="password" name="odoo_key" placeholder="{'(guardada)' if row['odoo_key'] else ''}" {'' if row['odoo_key'] else 'required'}></div>
</div>
<p class="nota">La API key se crea en Odoo: Ajustes de usuario → Seguridad de la cuenta → Claves API.
Se probará la conexión al guardar. Todas las claves se guardan cifradas.</p>
<button>Guardar y probar conexión</button></form></div>
{conexion}
<div class="card"><h2>{'3' if row['last_test'] else '2'} · Cómo trabaja tu empresa <span style="font-weight:400;font-size:.8rem">(opcional)</span></h2>
<form method="post" action="/panel/instrucciones">
<label>Instrucciones para tu IA</label>
<textarea name="instrucciones" placeholder="Ejemplo: Las órdenes de fabricación se crean siempre con su lista de materiales, indicando lote y subproductos. Los pedidos B2B llevan la tarifa mayorista...">{e(row['instrucciones'] or '')}</textarea>
<p class="nota">Todo lo que escribas aquí se entrega automáticamente a tu IA cada vez que se
conecta: tus convenciones, cómo creáis pedidos o fabricaciones, qué no debe tocar…
No hace falta repetirlo en cada conversación. Se aplica al guardar, sin reconectar nada.</p>
<button>Guardar instrucciones</button></form></div>
<div class="card"><h2>{'4' if row['last_test'] else '3'} · Claves de IA <span style="font-weight:400;font-size:.8rem">(para el chat de pruebas)</span></h2>
<form method="post" action="/panel/ia">
<label>Clave API de Claude (Anthropic)</label>
<input type="password" name="ai_claude" placeholder="{'(guardada)' if row['ai_claude'] else 'sk-ant-...'}">
<label>Otras claves (OpenAI, Gemini...)</label>
<input type="password" name="ai_otras" placeholder="{'(guardada)' if row['ai_otras'] else ''}">
<p class="nota">La clave de Claude activa el <a href="/chat">chat de pruebas</a> de este panel
(ideal si aún no tienes suscripción de Claude/ChatGPT). Se guarda cifrada. Para los conectores
no hace falta ninguna clave: ahí usas tu propia suscripción.</p>
<button>Guardar claves</button></form></div>
""", logged=True, admin=es_admin(row))


@panel_app.post("/panel/odoo")
def guardar_odoo(request: Request, odoo_url: str = Form(...), odoo_db: str = Form(...),
                 odoo_user: str = Form(...), odoo_key: str = Form("")):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    key = odoo_key.strip() or dec(row["odoo_key"])
    tenant = {"id": row["id"], "odoo_url": odoo_url.strip(), "odoo_db": odoo_db.strip(),
              "odoo_user": odoo_user.strip(), "odoo_key": key}
    try:
        info = probar_conexion(tenant)
        last_test = f"Odoo {info['version']} · usuario {info['usuario']}"
    except Exception as exc:
        return RedirectResponse(f"/panel?error=No se pudo conectar con Odoo: {str(exc)[:180]}", status_code=302)
    with db() as conn:
        conn.execute(
            "UPDATE tenants SET odoo_url=?, odoo_db=?, odoo_user=?, odoo_key=?, last_test=? WHERE id=?",
            (tenant["odoo_url"], tenant["odoo_db"], tenant["odoo_user"], enc(key), last_test, row["id"]),
        )
    return RedirectResponse("/panel?ok=Conexión con Odoo verificada y guardada", status_code=302)


@panel_app.post("/panel/instrucciones")
def guardar_instrucciones(request: Request, instrucciones: str = Form("")):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    with db() as conn:
        conn.execute("UPDATE tenants SET instrucciones=? WHERE id=?",
                     (instrucciones.strip(), row["id"]))
    return RedirectResponse("/panel?ok=Instrucciones guardadas — tu IA las recibirá en la próxima conversación", status_code=302)


@panel_app.post("/panel/ia")
def guardar_ia(request: Request, ai_claude: str = Form(""), ai_otras: str = Form("")):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    nueva_claude = enc(ai_claude.strip()) if ai_claude.strip() else row["ai_claude"]
    nueva_otras = enc(ai_otras.strip()) if ai_otras.strip() else row["ai_otras"]
    with db() as conn:
        conn.execute("UPDATE tenants SET ai_claude=?, ai_otras=? WHERE id=?",
                     (nueva_claude, nueva_otras, row["id"]))
    return RedirectResponse("/panel?ok=Claves de IA guardadas", status_code=302)


@panel_app.post("/panel/regenerar")
def regenerar(request: Request):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    with db() as conn:
        conn.execute("UPDATE tenants SET token=? WHERE id=?", (new_token(), row["id"]))
    return RedirectResponse("/panel?ok=Dirección regenerada — reconecta tus IAs con la nueva", status_code=302)


# ---------------------------------------------------------------- chat de demos

SYSTEM_CHAT = (
    "Eres el asistente de Odoo de la empresa del usuario, dentro del panel de Inhumario. "
    "Tienes herramientas para consultar y modificar su Odoo real. Responde en el idioma del "
    "usuario, con cifras claras. Antes de crear o modificar cualquier dato (odoo_crear, "
    "odoo_escribir, odoo_ejecutar con efectos), resume lo que vas a hacer y pide confirmación "
    "explícita en el chat. Para explorar un modelo desconocido usa odoo_campos u odoo_modelos."
)

_TOOL_OBJS = [srv.odoo_buscar, srv.odoo_contar, srv.odoo_leer, srv.odoo_crear, srv.odoo_escribir,
              srv.odoo_ejecutar, srv.odoo_campos, srv.odoo_modelos, srv.odoo_info]


def _anthropic_tools() -> list[dict]:
    return [{"name": t.name, "description": t.description or "", "input_schema": t.parameters}
            for t in _TOOL_OBJS]


def _ejecutar_tool(nombre: str, args: dict):
    for t in _TOOL_OBJS:
        if t.name == nombre:
            return t.fn(**args)
    raise ValueError(f"Herramienta desconocida: {nombre}")


@panel_app.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    avisos = []
    if not row["last_test"]:
        avisos.append('Configura primero tu <a href="/panel">conexión con Odoo</a>.')
    if not row["ai_claude"]:
        avisos.append('Guarda tu <a href="/panel">clave API de Claude</a> para activar el chat.')
    aviso_html = "".join(f'<div class="aviso-err">⚠️ {a}</div>' for a in avisos)
    deshabilitado = "disabled" if avisos else ""
    return page("Chat de pruebas", f"""
<div class="card"><h2>Chat de pruebas con tu Odoo</h2>
<p class="nota" style="margin-bottom:10px">Habla con tu Odoo usando tu clave API de Claude —
sin necesidad de suscripción. Ideal para probar antes de conectar tu IA habitual.
El coste de cada mensaje va contra tu clave API.</p>
{aviso_html}
<div id="chat-caja"><div class="msg msg-s">Prueba: «¿Cuántos pedidos llevamos este mes?» ·
«Busca al cliente García» · «¿Qué facturas están pendientes?»</div></div>
<form id="chat-form">
<input id="chat-texto" placeholder="Escribe tu pregunta..." autocomplete="off" {deshabilitado}>
<button {deshabilitado}>Enviar</button></form>
</div>
<script>
let historial = [];
const caja = document.getElementById('chat-caja');
function burbuja(cls, texto) {{
  const d = document.createElement('div'); d.className = 'msg ' + cls;
  d.textContent = texto; caja.appendChild(d); caja.scrollTop = caja.scrollHeight; return d;
}}
document.getElementById('chat-form').addEventListener('submit', async (ev) => {{
  ev.preventDefault();
  const input = document.getElementById('chat-texto');
  const texto = input.value.trim(); if (!texto) return;
  input.value = ''; input.disabled = true;
  burbuja('msg-u', texto);
  historial.push({{role: 'user', content: texto}});
  const espera = burbuja('msg-s', 'Consultando tu Odoo...');
  try {{
    const r = await fetch('/chat/enviar', {{method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{mensajes: historial}})}});
    const data = await r.json();
    espera.remove();
    if (data.error) {{ burbuja('msg-s', '❌ ' + data.error); }}
    else {{ historial = data.mensajes; burbuja('msg-a', data.texto); }}
  }} catch (err) {{ espera.remove(); burbuja('msg-s', '❌ Error de red: ' + err); }}
  input.disabled = false; input.focus();
}});
</script>
""", logged=True, admin=es_admin(row))


@panel_app.post("/chat/enviar")
def chat_enviar(request: Request, payload: dict):
    row = read_session(request)
    if not row:
        return JSONResponse({"error": "Sesión caducada, recarga la página"}, status_code=401)
    if not row["last_test"] or not row["odoo_url"]:
        return JSONResponse({"error": "Configura primero tu conexión con Odoo en el panel"})
    api_key = dec(row["ai_claude"])
    if not api_key:
        return JSONResponse({"error": "Guarda tu clave API de Claude en el panel"})

    mensajes = payload.get("mensajes", [])[-40:]
    if not mensajes:
        return JSONResponse({"error": "Mensaje vacío"})

    ctx = current_tenant.set(tenant_dict(row))
    try:
        client = anthropic.Anthropic(api_key=api_key)
        tools = _anthropic_tools()
        for _ in range(10):
            instrucciones = (row["instrucciones"] or "").strip()
            sistema = SYSTEM_CHAT if not instrucciones else (
                f"{SYSTEM_CHAT}\n\nNormas de trabajo de esta empresa (síguelas siempre):\n{instrucciones}")
            respuesta = client.messages.create(
                model="claude-opus-5",
                max_tokens=4096,
                system=sistema,
                messages=mensajes,
                tools=tools,
            )
            contenido = [b.model_dump() for b in respuesta.content]
            mensajes.append({"role": "assistant", "content": contenido})
            if respuesta.stop_reason == "refusal":
                return JSONResponse({"mensajes": mensajes,
                                     "texto": "El modelo ha rechazado la petición por políticas de seguridad."})
            if respuesta.stop_reason != "tool_use":
                texto = "".join(b.text for b in respuesta.content if b.type == "text")
                return JSONResponse({"mensajes": mensajes, "texto": texto or "(sin respuesta)"})
            resultados = []
            for b in respuesta.content:
                if b.type == "tool_use":
                    try:
                        r = _ejecutar_tool(b.name, b.input or {})
                        resultados.append({"type": "tool_result", "tool_use_id": b.id,
                                           "content": json.dumps(r, ensure_ascii=False, default=str)[:60000]})
                    except Exception as exc:
                        resultados.append({"type": "tool_result", "tool_use_id": b.id,
                                           "content": f"Error: {exc}", "is_error": True})
            mensajes.append({"role": "user", "content": resultados})
        return JSONResponse({"mensajes": mensajes,
                             "texto": "La consulta necesitó demasiados pasos; prueba a acotarla."})
    except anthropic.AuthenticationError:
        return JSONResponse({"error": "La clave API de Claude no es válida — revísala en el panel"})
    except anthropic.APIStatusError as exc:
        return JSONResponse({"error": f"Error de la API de Claude ({exc.status_code}): {exc.message[:150]}"})
    except Exception as exc:
        return JSONResponse({"error": f"Error inesperado: {str(exc)[:180]}"})
    finally:
        current_tenant.reset(ctx)


# ---------------------------------------------------------------- back office

@panel_app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, ok: str = "", error: str = ""):
    row = read_session(request)
    if not es_admin(row):
        return RedirectResponse("/login", status_code=302)
    msg = ""
    if ok:
        msg = f'<div class="aviso-ok">{e(ok)}</div>'
    if error:
        msg = f'<div class="aviso-err">{e(error)}</div>'
    with db() as conn:
        tenants = conn.execute("SELECT * FROM tenants ORDER BY id").fetchall()
        usos = dict(conn.execute(
            "SELECT tenant_id, COUNT(*) FROM usos WHERE fecha > datetime('now','-30 days') GROUP BY tenant_id"
        ).fetchall())
    filas = ""
    for t in tenants:
        estado = "🟢" if t["activo"] else "🔴"
        odoo = "✅" if t["last_test"] else "—"
        filas += f"""<tr><td>{t['id']}</td><td>{e(t['empresa'])}</td><td>{e(t['email'])}</td>
<td>{odoo}</td><td>{usos.get(t['id'], 0)}</td><td>{estado}</td><td style="white-space:nowrap">
<form method="post" action="/admin/toggle" style="display:inline"><input type="hidden" name="tid" value="{t['id']}">
<button class="btn-mini">{'Desactivar' if t['activo'] else 'Activar'}</button></form>
<form method="post" action="/admin/borrar" style="display:inline" onsubmit="return confirm('¿Borrar definitivamente a {e(t['empresa'])}? Su conexión dejará de funcionar.')">
<input type="hidden" name="tid" value="{t['id']}"><button class="btn-mini btn-rojo">Borrar</button></form>
</td></tr>"""
    return page("Administración", f"""
{msg}
<div class="card"><h2>Clientes ({len(tenants)})</h2>
<div class="tabla-scroll"><table>
<tr><th>ID</th><th>Empresa</th><th>Email</th><th>Odoo</th><th>Usos 30d</th><th>Estado</th><th>Acciones</th></tr>
{filas}</table></div>
<p class="nota">«Usos 30d» = llamadas a herramientas MCP en los últimos 30 días (la ruta legacy cuenta como ID 0).</p>
</div>
<div class="card"><h2>Dar de alta a un cliente</h2>
<form method="post" action="/admin/crear">
<div class="fila"><div><label>Empresa</label><input name="empresa" required></div>
<div><label>Email</label><input type="email" name="email" required></div></div>
<label>Contraseña provisional</label><input name="password" minlength="8" required>
<p class="nota">Entrega al cliente el email y la contraseña provisional; que la cambie… en la fase
siguiente (cambio de contraseña pendiente). Alternativa: dale el código de invitación
<b>{e(ALTA_CODIGO)}</b> y que se registre él en {e(BASE_URL)}/alta.</p>
<button>Crear cliente</button></form></div>
""", logged=True, admin=True)


@panel_app.post("/admin/crear")
def admin_crear(request: Request, empresa: str = Form(...), email: str = Form(...), password: str = Form(...)):
    row = read_session(request)
    if not es_admin(row):
        return RedirectResponse("/login", status_code=302)
    email = email.strip().lower()
    if tenant_by("email", email):
        return RedirectResponse("/admin?error=Ya existe una cuenta con ese email", status_code=302)
    with db() as conn:
        conn.execute("INSERT INTO tenants (empresa, email, pass_hash, token) VALUES (?,?,?,?)",
                     (empresa.strip(), email, hash_password(password), new_token()))
    return RedirectResponse(f"/admin?ok=Cliente {empresa} creado — entrégale sus credenciales", status_code=302)


@panel_app.post("/admin/toggle")
def admin_toggle(request: Request, tid: int = Form(...)):
    row = read_session(request)
    if not es_admin(row):
        return RedirectResponse("/login", status_code=302)
    with db() as conn:
        conn.execute("UPDATE tenants SET activo = 1 - activo WHERE id=?", (tid,))
    return RedirectResponse("/admin?ok=Estado cambiado", status_code=302)


@panel_app.post("/admin/borrar")
def admin_borrar(request: Request, tid: int = Form(...)):
    row = read_session(request)
    if not es_admin(row):
        return RedirectResponse("/login", status_code=302)
    if row["id"] == tid:
        return RedirectResponse("/admin?error=No puedes borrarte a ti mismo", status_code=302)
    with db() as conn:
        conn.execute("DELETE FROM tenants WHERE id=?", (tid,))
        conn.execute("DELETE FROM usos WHERE tenant_id=?", (tid,))
    return RedirectResponse("/admin?ok=Cliente borrado", status_code=302)
