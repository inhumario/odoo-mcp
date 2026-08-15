"""
MCP de Odoo — Inhumario (multi-tenant)
======================================

Servidor MCP (Streamable HTTP) que expone el Odoo de CADA cliente por XML-RPC.
Las credenciales del cliente activo llegan por contextvar (`current_tenant`),
que fija el dispatcher de app.py a partir del token de la URL.

Compatibilidad: si MCP_PATH + ODOO_* están en el entorno, esa ruta "legacy"
sigue sirviendo el tenant del entorno (el conector original de Mario).
"""

import contextvars
import json
import xmlrpc.client
from typing import Any

from fastmcp import FastMCP

# Tenant activo en esta petición: dict con odoo_url, odoo_db, odoo_user, odoo_key
current_tenant: contextvars.ContextVar[dict] = contextvars.ContextVar("current_tenant")

# Cache de uid por credenciales (los tenants cambian poco)
_uid_cache: dict[tuple, int] = {}

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
        return _proxy("object", t["odoo_url"]).execute_kw(
            t["odoo_db"], _auth(t), t["odoo_key"], model, method, args, kwargs or {}
        )
    except xmlrpc.client.Fault:
        _uid_cache.pop(key, None)
        return _proxy("object", t["odoo_url"]).execute_kw(
            t["odoo_db"], _auth(t), t["odoo_key"], model, method, args, kwargs or {}
        )


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
