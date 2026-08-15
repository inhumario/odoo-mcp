"""
Panel de clientes + dispatcher MCP multi-tenant — Inhumario
===========================================================

- Panel web en /: alta, login, credenciales de Odoo, URL MCP propia e
  instrucciones para conectarla a Claude, ChatGPT u otra IA compatible MCP.
- MCP por tenant en /t/<token>/mcp (el token identifica al cliente).
- Ruta legacy (MCP_PATH + ODOO_* del entorno) para el conector original.

Variables de entorno:
  SECRET_KEY   — firma de cookies de sesión (obligatoria)
  ALTA_CODIGO  — código de invitación para el alta (obligatoria)
  DB_PATH      — sqlite, por defecto /data/tenants.db
  MCP_PATH, ODOO_URL, ODOO_DB, ODOO_USER, ODOO_API_KEY — tenant legacy (opcional)
  PORT         — puerto (uvicorn lo lee del CMD)
"""

import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from server import mcp, current_tenant, probar_conexion

SECRET_KEY = os.environ["SECRET_KEY"]
ALTA_CODIGO = os.environ.get("ALTA_CODIGO", "")
DB_PATH = os.environ.get("DB_PATH", "/data/tenants.db")
BASE_URL = os.environ.get("BASE_URL", "https://mcp.inhumario.com")

LEGACY_PATH = os.environ.get("MCP_PATH", "").strip("/")
LEGACY_TENANT = None
if LEGACY_PATH and os.environ.get("ODOO_URL"):
    LEGACY_TENANT = {
        "odoo_url": os.environ["ODOO_URL"],
        "odoo_db": os.environ["ODOO_DB"],
        "odoo_user": os.environ["ODOO_USER"],
        "odoo_key": os.environ["ODOO_API_KEY"],
    }

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


def tenant_by(field: str, value: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(f"SELECT * FROM tenants WHERE {field} = ?", (value,)).fetchone()


# ---------------------------------------------------------------- auth helpers

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


def new_token() -> str:
    return "mcp-" + secrets.token_hex(24)


# ---------------------------------------------------------------- dispatcher MCP

mcp_app = mcp.http_app(path="/mcp", stateless_http=True)


async def _plain_response(send, status: int, text: str) -> None:
    body = text.encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
    await send({"type": "http.response.body", "body": body})


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
            if row is None or not row["odoo_url"]:
                return await _plain_response(send, 404, "Tenant no encontrado o sin credenciales de Odoo configuradas")
            tenant = {"odoo_url": row["odoo_url"], "odoo_db": row["odoo_db"],
                      "odoo_user": row["odoo_user"], "odoo_key": row["odoo_key"]}
            return await self._delegate_mcp(tenant, scope, receive, send)
        if LEGACY_TENANT and path.rstrip("/") == "/" + LEGACY_PATH:
            return await self._delegate_mcp(LEGACY_TENANT, scope, receive, send)
        return await self.panel(scope, receive, send)


# ---------------------------------------------------------------- FastAPI

panel_app = FastAPI(lifespan=mcp_app.lifespan)
init_db()
app = RootDispatcher(panel_app, mcp_app)


# ---------------------------------------------------------------- HTML

CSS = """
:root { --verde-osc:#0E4A31; --verde:#1F7A50; --verde-cl:#35996A; --fondo:#F5FAF7;
        --cabecera:#EAF4EE; --borde:#C9DED3; --texto:#1F2D26; }
* { box-sizing:border-box; margin:0; }
body { font-family:-apple-system,'Segoe UI',Roboto,sans-serif; background:var(--fondo);
       color:var(--texto); line-height:1.55; }
header { background:var(--verde-osc); color:#fff; padding:14px 20px; display:flex;
         justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; }
header h1 { font-size:1.15rem; font-weight:600; }
header a { color:#EAF4EE; text-decoration:none; font-size:.9rem; }
main { max-width:860px; margin:24px auto; padding:0 16px 48px; }
.card { background:#fff; border:1px solid var(--borde); border-radius:10px;
        padding:22px; margin-bottom:20px; }
.card h2 { color:var(--verde-osc); font-size:1.05rem; margin-bottom:12px;
           border-bottom:2px solid var(--verde-cl); padding-bottom:6px; }
label { display:block; font-size:.85rem; font-weight:600; margin:10px 0 4px; }
input { width:100%; padding:10px; border:1px solid var(--borde); border-radius:6px;
        font-size:.95rem; }
button { background:var(--verde); color:#fff; border:0; border-radius:6px;
         padding:11px 20px; font-size:.95rem; font-weight:600; cursor:pointer; margin-top:14px; }
button:hover { background:var(--verde-osc); }
.aviso-ok { background:var(--cabecera); border:1px solid var(--verde-cl); color:var(--verde-osc);
            padding:10px 14px; border-radius:6px; margin-bottom:14px; font-size:.9rem; }
.aviso-err { background:#FBEDEA; border:1px solid #E0B4AB; color:#7A2E1F;
             padding:10px 14px; border-radius:6px; margin-bottom:14px; font-size:.9rem; }
.url-mcp { background:var(--cabecera); border:1px dashed var(--verde-cl); border-radius:6px;
           padding:12px; font-family:ui-monospace,monospace; font-size:.8rem;
           word-break:break-all; margin:8px 0; }
.pasos li { margin-bottom:8px; }
.nota { font-size:.82rem; color:#5A6E63; margin-top:6px; }
.fila { display:flex; gap:14px; flex-wrap:wrap; }
.fila > div { flex:1; min-width:220px; }
@media (max-width:600px){ .card{padding:16px} main{margin-top:14px} }
"""


def page(title: str, body: str, logged: bool = False) -> HTMLResponse:
    nav = '<a href="/salir">Cerrar sesión</a>' if logged else ""
    return HTMLResponse(f"""<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Inhumario MCP</title><style>{CSS}</style></head><body>
<header><h1>🔌 Inhumario · Odoo para tu IA</h1>{nav}</header>
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
    row = tenant_by("email", email.strip().lower())
    if not row or not check_password(password, row["pass_hash"]):
        return RedirectResponse("/login?error=Email o contraseña incorrectos", status_code=302)
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
<form method="post" action="/panel/regenerar" onsubmit="return confirm('Si regeneras la dirección, la actual dejará de funcionar y tendrás que reconectar tus IAs. ¿Continuar?')">
<button style="background:#8C2F1F">Regenerar dirección (si se ha filtrado)</button></form>
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
Se probará la conexión al guardar.</p>
<button>Guardar y probar conexión</button></form></div>
{conexion}
<div class="card"><h2>{'3' if row['last_test'] else '2'} · Claves de IA <span style="font-weight:400;font-size:.8rem">(opcional — para el chat integrado, próximamente)</span></h2>
<form method="post" action="/panel/ia">
<label>Clave API de Claude (Anthropic)</label>
<input type="password" name="ai_claude" placeholder="{'(guardada)' if row['ai_claude'] else 'sk-ant-...'}">
<label>Otras claves (OpenAI, Gemini...)</label>
<input type="password" name="ai_otras" placeholder="{'(guardada)' if row['ai_otras'] else ''}">
<p class="nota">No hacen falta para conectar tu IA por conector: ahí usas tu propia suscripción.
Estas claves solo se usarán para el futuro chat integrado en este panel.</p>
<button>Guardar claves</button></form></div>
""", logged=True)


@panel_app.post("/panel/odoo")
def guardar_odoo(request: Request, odoo_url: str = Form(...), odoo_db: str = Form(...),
                 odoo_user: str = Form(...), odoo_key: str = Form("")):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    key = odoo_key.strip() or row["odoo_key"]
    tenant = {"odoo_url": odoo_url.strip(), "odoo_db": odoo_db.strip(),
              "odoo_user": odoo_user.strip(), "odoo_key": key}
    try:
        info = probar_conexion(tenant)
        last_test = f"Odoo {info['version']} · usuario {info['usuario']}"
    except Exception as exc:
        return RedirectResponse(f"/panel?error=No se pudo conectar con Odoo: {str(exc)[:180]}", status_code=302)
    with db() as conn:
        conn.execute(
            "UPDATE tenants SET odoo_url=?, odoo_db=?, odoo_user=?, odoo_key=?, last_test=? WHERE id=?",
            (tenant["odoo_url"], tenant["odoo_db"], tenant["odoo_user"], key, last_test, row["id"]),
        )
    return RedirectResponse("/panel?ok=Conexión con Odoo verificada y guardada", status_code=302)


@panel_app.post("/panel/ia")
def guardar_ia(request: Request, ai_claude: str = Form(""), ai_otras: str = Form("")):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    with db() as conn:
        conn.execute("UPDATE tenants SET ai_claude=?, ai_otras=? WHERE id=?",
                     (ai_claude.strip() or row["ai_claude"], ai_otras.strip() or row["ai_otras"], row["id"]))
    return RedirectResponse("/panel?ok=Claves de IA guardadas", status_code=302)


@panel_app.post("/panel/regenerar")
def regenerar(request: Request):
    row = read_session(request)
    if not row:
        return RedirectResponse("/login", status_code=302)
    with db() as conn:
        conn.execute("UPDATE tenants SET token=? WHERE id=?", (new_token(), row["id"]))
    return RedirectResponse("/panel?ok=Dirección regenerada — reconecta tus IAs con la nueva", status_code=302)
