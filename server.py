"""
MCP de Odoo — Inhumario (multi-tenant)
======================================

Servidor MCP (Streamable HTTP) que expone el Odoo de CADA cliente por XML-RPC.
Las credenciales del cliente activo llegan por contextvar (`current_tenant`),
que fija el dispatcher de app.py a partir del token de la URL.

Compatibilidad: si MCP_PATH + ODOO_* están en el entorno, esa ruta "legacy"
sigue sirviendo el tenant del entorno (el conector original de Mario).
"""

import base64
import contextvars
import datetime as _dt
import email
import email.header
import html
import imaplib
import ipaddress
import json
import mimetypes
import re
import socket
import urllib.parse
import urllib.request
import xmlrpc.client
from typing import Any

from fastmcp import FastMCP

# Tenant activo en esta petición: dict con id, odoo_url, odoo_db, odoo_user, odoo_key
current_tenant: contextvars.ContextVar[dict] = contextvars.ContextVar("current_tenant")

# Cache de uid por credenciales (los tenants cambian poco)
_uid_cache: dict[tuple, int] = {}

# Hook opcional que fija app.py para registrar el uso: fn(tenant_id, modelo, metodo)
USAGE_LOGGER = None

MAX_CHARS = 100_000


def _tenant() -> dict:
    try:
        return current_tenant.get()
    except LookupError:
        raise RuntimeError("Sin tenant activo: la petición no llegó por una URL de cliente válida")


def _proxy(endpoint: str, url: str) -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(f"{url.rstrip('/')}/xmlrpc/2/{endpoint}", allow_none=True)


def _auth(t: dict) -> int:
    key = (t["odoo_url"], t["odoo_db"], t["odoo_user"], t["odoo_key"])
    if key not in _uid_cache:
        uid = _proxy("common", t["odoo_url"]).authenticate(t["odoo_db"], t["odoo_user"], t["odoo_key"], {})
        if not uid:
            raise RuntimeError("Autenticación con Odoo fallida: revisa usuario y API key en el panel")
        _uid_cache[key] = uid
    return _uid_cache[key]


def probar_conexion(t: dict) -> dict:
    """Usado por el panel para validar credenciales. Lanza excepción si algo falla."""
    version = _proxy("common", t["odoo_url"]).version()
    uid = _auth(t)
    user = _proxy("object", t["odoo_url"]).execute_kw(
        t["odoo_db"], uid, t["odoo_key"], "res.users", "read", [[uid]], {"fields": ["name", "login"]}
    )
    return {"version": version.get("server_version"), "usuario": user[0]["name"], "login": user[0]["login"]}


def _execute(model: str, method: str, args: list, kwargs: dict | None = None) -> Any:
    t = _tenant()
    key = (t["odoo_url"], t["odoo_db"], t["odoo_user"], t["odoo_key"])
    try:
        result = _proxy("object", t["odoo_url"]).execute_kw(
            t["odoo_db"], _auth(t), t["odoo_key"], model, method, args, kwargs or {}
        )
    except xmlrpc.client.Fault:
        _uid_cache.pop(key, None)
        result = _proxy("object", t["odoo_url"]).execute_kw(
            t["odoo_db"], _auth(t), t["odoo_key"], model, method, args, kwargs or {}
        )
    if USAGE_LOGGER:
        try:
            USAGE_LOGGER(t.get("id"), model, method)
        except Exception:
            pass
    return result


def _clean(value: Any) -> Any:
    if isinstance(value, bytes):
        return f"<binario: {len(value)} bytes omitidos>"
    if isinstance(value, xmlrpc.client.DateTime):
        return str(value)
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _result(value: Any) -> Any:
    value = _clean(value)
    text = json.dumps(value, ensure_ascii=False, default=str)
    if len(text) > MAX_CHARS:
        return {
            "truncado": True,
            "aviso": f"Respuesta de {len(text)} caracteres truncada a {MAX_CHARS}. "
                     "Pide menos campos, usa limit/offset o filtra más el domain.",
            "datos_parciales": text[:MAX_CHARS],
        }
    return value


mcp = FastMCP(
    "Odoo por Inhumario",
    instructions=(
        "Acceso al Odoo de la empresa del usuario vía XML-RPC. "
        "Modelos habituales: sale.order (pedidos), account.move (facturas/asientos), "
        "res.partner (clientes/proveedores), product.template y product.product (productos), "
        "stock.picking (albaranes). Fechas en formato 'YYYY-MM-DD'. "
        "Antes de escribir en un modelo que no conozcas, consulta sus campos con odoo_campos. "
        "PRECAUCIÓN: normalmente es la base de datos de PRODUCCIÓN de la empresa — confirma "
        "con el usuario antes de crear, modificar o ejecutar acciones con efecto contable."
    ),
)


# Instrucciones por tenant: el campo "instrucciones" del panel se añade a las
# instructions del servidor MCP en cada initialize. En stateless_http el SDK llama
# a create_initialization_options() por petición, con el contextvar ya fijado por
# el dispatcher, así que cada cliente recibe su propio "manual de la casa".
def _instrucciones_tenant() -> str:
    try:
        return (current_tenant.get().get("instrucciones") or "").strip()
    except LookupError:
        return ""


_orig_init_options = mcp._mcp_server.create_initialization_options


def _buzon_tenant() -> dict | None:
    """Config del buzón de adjuntos del tenant (host, user, pass, direccion) o None."""
    try:
        t = current_tenant.get()
    except LookupError:
        return None
    if t.get("buzon_host") and t.get("buzon_user") and t.get("buzon_pass"):
        return {"host": t["buzon_host"], "user": t["buzon_user"], "pass": t["buzon_pass"],
                "direccion": (t.get("buzon_direccion") or t["buzon_user"]).strip()}
    return None


def _init_options_con_instrucciones(*args, **kwargs):
    opts = _orig_init_options(*args, **kwargs)
    partes = []
    extra = _instrucciones_tenant()
    if extra:
        partes.append("## Normas de trabajo de esta empresa (síguelas siempre, sin que el usuario las pida)\n\n" + extra)
    buzon = _buzon_tenant()
    if buzon:
        partes.append(
            "## Buzón de adjuntos (activo)\n\n"
            f"Para adjuntar a un registro de Odoo un fichero que está en un email (p.ej. el PDF de una "
            f"factura de proveedor): reenvía ese email, con sus adjuntos, a **{buzon['direccion']}** y "
            "después llama a `odoo_adjuntar_desde_buzon` indicando en `buscar` un texto que identifique "
            "el mensaje (número de factura, asunto…). Si el fichero está en una URL pública o es pequeño, "
            "usa `odoo_adjuntar`. Nunca des por terminada una factura de proveedor sin su PDF adjunto."
        )
    if partes:
        base = opts.instructions or ""
        opts = opts.model_copy(update={"instructions": base + "\n\n" + "\n\n".join(partes)})
    return opts


mcp._mcp_server.create_initialization_options = _init_options_con_instrucciones


@mcp.tool
def odoo_buscar(
    model: str,
    domain: list | None = None,
    fields: list[str] | None = None,
    limit: int = 20,
    offset: int = 0,
    order: str | None = None,
) -> Any:
    """Busca y lee registros de un modelo de Odoo (search_read).

    Args:
        model: modelo Odoo, p.ej. 'sale.order', 'res.partner', 'account.move'.
        domain: filtro Odoo, p.ej. [["date_order", ">=", "2026-08-01"], ["state", "=", "sale"]].
            Vacío o null = todos.
        fields: lista de campos a devolver, p.ej. ["name", "partner_id", "amount_total"].
            Si se omite devuelve todos (puede ser enorme — mejor especificar).
        limit: máximo de registros (por defecto 20).
        offset: desplazamiento para paginar.
        order: ordenación, p.ej. 'date_order desc'.
    """
    kwargs: dict[str, Any] = {"limit": limit, "offset": offset}
    if fields:
        kwargs["fields"] = fields
    if order:
        kwargs["order"] = order
    return _result(_execute(model, "search_read", [domain or []], kwargs))


@mcp.tool
def odoo_contar(model: str, domain: list | None = None) -> Any:
    """Cuenta cuántos registros de un modelo cumplen un filtro (search_count).

    Args:
        model: modelo Odoo, p.ej. 'sale.order'.
        domain: filtro Odoo; vacío o null = todos.
    """
    return _result(_execute(model, "search_count", [domain or []]))


@mcp.tool
def odoo_leer(model: str, ids: list[int], fields: list[str] | None = None) -> Any:
    """Lee registros concretos por sus IDs (read).

    Args:
        model: modelo Odoo.
        ids: lista de IDs a leer.
        fields: campos a devolver; si se omite devuelve todos.
    """
    kwargs = {"fields": fields} if fields else {}
    return _result(_execute(model, "read", [ids], kwargs))


@mcp.tool
def odoo_crear(model: str, values: dict) -> Any:
    """Crea un registro en Odoo (create). Devuelve el ID del registro nuevo.

    Args:
        model: modelo Odoo, p.ej. 'sale.order' o 'res.partner'.
        values: diccionario de campos. Para líneas one2many usa la sintaxis de comandos
            de Odoo, p.ej. "order_line": [[0, 0, {"product_id": 123, "product_uom_qty": 2}]].
    """
    return _result(_execute(model, "create", [values]))


@mcp.tool
def odoo_escribir(model: str, ids: list[int], values: dict) -> Any:
    """Modifica registros existentes (write).

    Args:
        model: modelo Odoo.
        ids: IDs de los registros a modificar.
        values: campos a cambiar.
    """
    return _result(_execute(model, "write", [ids, values]))


@mcp.tool
def odoo_ejecutar(model: str, method: str, args: list | None = None, kwargs: dict | None = None) -> Any:
    """Ejecuta cualquier método de un modelo de Odoo (execute_kw genérico).

    Para lo que no cubren las demás herramientas: confirmar un pedido
    (method='action_confirm', args=[[id]]), publicar una factura (method='action_post'),
    read_group para agregados, name_search, etc.

    Args:
        model: modelo Odoo.
        method: nombre del método.
        args: argumentos posicionales (normalmente el primero es la lista de IDs).
        kwargs: argumentos con nombre.
    """
    return _result(_execute(model, method, args or [], kwargs))


@mcp.tool
def odoo_campos(model: str, solo_nombres: bool = False) -> Any:
    """Devuelve los campos de un modelo con tipo y descripción (fields_get).

    Args:
        model: modelo Odoo, p.ej. 'sale.order'.
        solo_nombres: si true devuelve solo la lista de nombres de campo (mucho más corto).
    """
    data = _execute(model, "fields_get", [], {"attributes": ["string", "type", "relation", "required", "readonly"]})
    if solo_nombres:
        return _result(sorted(data.keys()))
    return _result(data)


@mcp.tool
def odoo_modelos(buscar: str) -> Any:
    """Busca modelos de Odoo por nombre técnico o descripción (ir.model).

    Args:
        buscar: texto a buscar, p.ej. 'pedido', 'sale', 'banco'.
    """
    domain = ["|", ["model", "ilike", buscar], ["name", "ilike", buscar]]
    return _result(_execute("ir.model", "search_read", [domain], {"fields": ["model", "name"], "limit": 50}))


@mcp.tool
def odoo_info() -> Any:
    """Comprueba la conexión con Odoo y devuelve versión del servidor y usuario conectado."""
    t = _tenant()
    return _result(probar_conexion(t))


# ---------------------------------------------------------------- adjuntos

MAX_ADJUNTO = 25 * 1024 * 1024  # 25 MB


def _adjuntos_existentes(model: str, res_id: int) -> list[dict]:
    return _execute("ir.attachment", "search_read",
                    [[["res_model", "=", model], ["res_id", "=", res_id]]],
                    {"fields": ["id", "name", "file_size", "mimetype"]})


def _crear_adjunto(model: str, res_id: int, nombre: str, contenido: bytes, mimetype: str | None = None) -> dict:
    """Crea un ir.attachment sobre el registro. Si ya hay uno con mismo nombre y tamaño, no duplica."""
    if not contenido:
        raise ValueError(f"El fichero {nombre} está vacío")
    if len(contenido) > MAX_ADJUNTO:
        raise ValueError(f"El fichero {nombre} pesa {len(contenido)//1024} KB; máximo {MAX_ADJUNTO//1024//1024} MB")
    mimetype = mimetype or mimetypes.guess_type(nombre)[0] or "application/octet-stream"
    for a in _adjuntos_existentes(model, res_id):
        if a["name"] == nombre and a["file_size"] == len(contenido):
            return {"id": a["id"], "nombre": nombre, "bytes": len(contenido), "duplicado": True,
                    "aviso": "Ya existía un adjunto idéntico en el registro; no se ha duplicado"}
    att_id = _execute("ir.attachment", "create", [{
        "name": nombre, "res_model": model, "res_id": res_id, "type": "binary",
        "mimetype": mimetype, "datas": base64.b64encode(contenido).decode(),
    }])
    return {"id": att_id, "nombre": nombre, "bytes": len(contenido), "mimetype": mimetype, "duplicado": False}


def _comprobar_registro(model: str, res_id: int) -> str:
    """Verifica que el registro existe y devuelve su display_name."""
    r = _execute(model, "read", [[res_id]], {"fields": ["display_name"]})
    if not r:
        raise ValueError(f"No existe {model} con id {res_id}")
    return r[0]["display_name"]


def _url_segura(url: str) -> None:
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Solo se admiten URLs http(s) públicas")
    for info in socket.getaddrinfo(p.hostname, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("La URL apunta a una dirección privada; no se permite")


def _descargar(url: str) -> tuple[bytes, str | None, str]:
    _url_segura(url)
    req = urllib.request.Request(url, headers={"User-Agent": "Inhumario-MCP/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read(MAX_ADJUNTO + 1)
        ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip() or None
        nombre = ""
        cd = r.headers.get("Content-Disposition") or ""
        m = [x for x in cd.split(";") if "filename=" in x]
        if m:
            nombre = m[0].split("=", 1)[1].strip().strip('"')
    if not nombre:
        nombre = urllib.parse.unquote(urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]) or "adjunto"
    return data, ctype, nombre


@mcp.tool
def odoo_adjuntar(
    model: str,
    res_id: int,
    nombre: str | None = None,
    contenido_base64: str | None = None,
    url: str | None = None,
) -> Any:
    """Adjunta un fichero a un registro de Odoo (ir.attachment), p.ej. el PDF de una factura.

    Indica UNA fuente: `contenido_base64` (fichero pequeño codificado en base64) o `url`
    (dirección http(s) pública desde la que el servidor descarga el fichero).
    Si el fichero está en un email, usa `odoo_adjuntar_desde_buzon` en su lugar.

    Args:
        model: modelo del registro, p.ej. 'account.move' (factura), 'purchase.order', 'res.partner'.
        res_id: ID del registro al que se adjunta.
        nombre: nombre del fichero con extensión, p.ej. 'Factura R1169785.pdf'.
            Obligatorio con contenido_base64; con url se deduce si se omite.
        contenido_base64: contenido del fichero en base64.
        url: URL pública del fichero.
    """
    if bool(contenido_base64) == bool(url):
        raise ValueError("Indica exactamente una fuente: contenido_base64 o url")
    registro = _comprobar_registro(model, res_id)
    if contenido_base64:
        if not nombre:
            raise ValueError("Con contenido_base64 hay que indicar el nombre del fichero")
        contenido, mimetype = base64.b64decode(contenido_base64), None
    else:
        contenido, mimetype, nombre_url = _descargar(url)
        nombre = nombre or nombre_url
    res = _crear_adjunto(model, res_id, nombre, contenido, mimetype)
    return _result({"registro": registro, "adjunto": res})


def _decodificar_cabecera(valor) -> str:
    if not valor:
        return ""
    try:
        return str(email.header.make_header(email.header.decode_header(valor)))
    except Exception:
        return str(valor)


def _texto_plano(msg) -> str:
    """Texto del cuerpo (partes text/plain y text/html sin etiquetas) para buscar en él."""
    trozos = []
    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.get_filename():
            continue
        try:
            texto = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")
        except Exception:
            continue
        if part.get_content_subtype() == "html":
            texto = html.unescape(re.sub(r"<[^>]+>", " ", texto))
        trozos.append(texto)
    return "\n".join(trozos)


def _adjuntos_de(msg) -> list[tuple[str, bytes, str]]:
    out = []
    for part in msg.walk():
        nombre = part.get_filename()
        if not nombre or part.get_content_maintype() == "multipart":
            continue
        nombre = _decodificar_cabecera(nombre)
        datos = part.get_payload(decode=True) or b""
        out.append((nombre, datos, part.get_content_type()))
    return out


def _carpeta_todos(m: imaplib.IMAP4) -> str:
    """Carpeta que contiene todo el correo (\\All en Gmail, INBOX en el resto)."""
    try:
        typ, carpetas = m.list()
        for c in carpetas or []:
            linea = c.decode(errors="replace") if isinstance(c, bytes) else str(c)
            if "\\All" in linea:
                return linea.rsplit(" ", 1)[-1]
    except Exception:
        pass
    return "INBOX"


def probar_buzon(cfg: dict) -> dict:
    """Usado por el panel: comprueba login IMAP y devuelve la carpeta que se leerá."""
    m = imaplib.IMAP4_SSL(cfg["host"], timeout=20)
    try:
        m.login(cfg["user"], cfg["pass"])
        carpeta = _carpeta_todos(m)
        typ, _ = m.select(carpeta, readonly=True)
        if typ != "OK":
            raise RuntimeError(f"No se pudo abrir la carpeta {carpeta}")
        return {"carpeta": carpeta}
    finally:
        try:
            m.logout()
        except Exception:
            pass


def _mensajes_buzon(cfg: dict, dias: int, maximo: int = 25) -> list[tuple[bytes, Any]]:
    """Devuelve [(uid, mensaje)] del buzón, los más recientes primero."""
    m = imaplib.IMAP4_SSL(cfg["host"], timeout=30)
    try:
        m.login(cfg["user"], cfg["pass"])
        m.select(_carpeta_todos(m), readonly=True)
        desde = (_dt.date.today() - _dt.timedelta(days=dias)).strftime("%d-%b-%Y")
        criterios = ["SINCE", desde]
        if cfg.get("direccion"):
            criterios += ["TO", cfg["direccion"]]
        typ, data = m.uid("search", None, *criterios)
        uids = (data[0] or b"").split()
        uids = uids[-maximo:][::-1]
        out = []
        for uid in uids:
            typ, partes = m.uid("fetch", uid, "(RFC822)")
            for p in partes or []:
                if isinstance(p, tuple) and len(p) > 1:
                    out.append((uid, email.message_from_bytes(p[1])))
        return out
    finally:
        try:
            m.logout()
        except Exception:
            pass


@mcp.tool
def odoo_adjuntar_desde_buzon(
    model: str,
    res_id: int,
    buscar: str | None = None,
    nombre_adjunto: str | None = None,
    tipos: list[str] | None = None,
    dias: int = 3,
    solo_listar: bool = False,
) -> Any:
    """Adjunta a un registro de Odoo los ficheros de un email recibido en el buzón de adjuntos.

    Flujo: primero reenvía el email que contiene el fichero (p.ej. el PDF de la factura) a la
    dirección del buzón de adjuntos que aparece en las instrucciones de este servidor; después
    llama a esta herramienta. Se toma el mensaje MÁS RECIENTE del buzón que encaje con `buscar`
    y se adjuntan sus ficheros (por defecto solo PDF) al registro. No duplica adjuntos idénticos.

    Args:
        model: modelo del registro, p.ej. 'account.move' (factura de proveedor).
        res_id: ID del registro.
        buscar: texto que identifica el email (nº de factura, asunto, remitente…). Se busca en
            asunto, remitente, cuerpo y nombres de adjuntos, sin distinguir mayúsculas. Si se
            omite, se usa el email más reciente del buzón que tenga adjuntos.
        nombre_adjunto: si el email trae varios ficheros, texto que debe contener el nombre del
            que se quiere adjuntar.
        tipos: extensiones admitidas, por defecto ["pdf"]. Usa ["*"] para adjuntar todo.
        dias: cuántos días hacia atrás mirar en el buzón (por defecto 3).
        solo_listar: si true, no adjunta nada: devuelve los emails del buzón que encajan y sus
            ficheros, para comprobar antes.
    """
    cfg = _buzon_tenant()
    if not cfg:
        raise RuntimeError("Este cliente no tiene configurado el buzón de adjuntos (panel → Buzón de adjuntos)")
    tipos = [t.lower().lstrip(".") for t in (tipos or ["pdf"])]
    aguja = (buscar or "").strip().lower()
    candidatos = []
    for uid, msg in _mensajes_buzon(cfg, max(1, min(dias, 60))):
        adj = _adjuntos_de(msg)
        if not adj:
            continue
        asunto = _decodificar_cabecera(msg.get("Subject"))
        remitente = _decodificar_cabecera(msg.get("From"))
        if aguja:
            pajar = " ".join([asunto, remitente, _texto_plano(msg)] + [n for n, _, _ in adj]).lower()
            if aguja not in pajar:
                continue
        candidatos.append({"uid": uid.decode(), "asunto": asunto, "de": remitente,
                           "fecha": msg.get("Date"), "ficheros": [(n, len(d), ct) for n, d, ct in adj],
                           "_adj": adj})
    if solo_listar:
        return _result([{k: v for k, v in c.items() if k != "_adj"} for c in candidatos])
    if not candidatos:
        raise RuntimeError(
            f"No hay en el buzón ({cfg['direccion']}, últimos {dias} días) ningún email con adjuntos"
            + (f" que contenga «{buscar}»" if buscar else "")
            + ". Reenvía primero el email al buzón y vuelve a intentarlo (puede tardar unos segundos en llegar)."
        )
    registro = _comprobar_registro(model, res_id)
    elegido = candidatos[0]
    resultados, omitidos = [], []
    for nombre, datos, ctype in elegido["_adj"]:
        ext = nombre.rsplit(".", 1)[-1].lower() if "." in nombre else ""
        if "*" not in tipos and ext not in tipos:
            omitidos.append(f"{nombre} (tipo .{ext} no pedido)")
            continue
        if nombre_adjunto and nombre_adjunto.lower() not in nombre.lower():
            omitidos.append(f"{nombre} (no contiene «{nombre_adjunto}»)")
            continue
        resultados.append(_crear_adjunto(model, res_id, nombre, datos, ctype))
    if not resultados:
        raise RuntimeError(f"El email «{elegido['asunto']}» no tiene ficheros que encajen. Omitidos: {omitidos}")
    return _result({"registro": registro, "email": {k: v for k, v in elegido.items() if k not in ("_adj", "ficheros")},
                    "adjuntados": resultados, "omitidos": omitidos,
                    "otros_emails_que_encajaban": len(candidatos) - 1})
