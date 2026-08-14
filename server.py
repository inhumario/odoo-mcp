"""
MCP de Odoo — Aromas de Té (piloto)
===================================

Servidor MCP remoto (Streamable HTTP) que expone el Odoo de Aromas por XML-RPC,
para usarlo como conector personalizado en Claude (web y móvil).

SIN restricciones de permisos: usa la API key del usuario configurado en las
variables de entorno y hereda sus permisos de Odoo. La única barrera de acceso
es la ruta secreta (MCP_PATH) — fase 2: OAuth + herramientas por rol.

Variables de entorno:
  ODOO_URL, ODOO_DB, ODOO_USER, ODOO_API_KEY  — conexión XML-RPC
  MCP_PATH  — ruta secreta del endpoint, p.ej. /mcp-a1b2c3... (obligatoria)
  PORT      — puerto HTTP (por defecto 8000)
"""

import json
import os
import xmlrpc.client
from typing import Any

from fastmcp import FastMCP

ODOO_URL = os.environ["ODOO_URL"].rstrip("/")
ODOO_DB = os.environ["ODOO_DB"]
ODOO_USER = os.environ["ODOO_USER"]
ODOO_API_KEY = os.environ["ODOO_API_KEY"]

_uid: int | None = None

# Límite de caracteres de cualquier respuesta para no reventar el contexto
MAX_CHARS = 100_000


def _common() -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(f"{ODOO_URL}/xmlrpc/2/common", allow_none=True)


def _models() -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(f"{ODOO_URL}/xmlrpc/2/object", allow_none=True)


def _get_uid() -> int:
    global _uid
    if _uid is None:
        uid = _common().authenticate(ODOO_DB, ODOO_USER, ODOO_API_KEY, {})
        if not uid:
            raise RuntimeError("Autenticación con Odoo fallida: revisa ODOO_USER / ODOO_API_KEY")
        _uid = uid
    return _uid


def _execute(model: str, method: str, args: list, kwargs: dict | None = None) -> Any:
    global _uid
    try:
        return _models().execute_kw(ODOO_DB, _get_uid(), ODOO_API_KEY, model, method, args, kwargs or {})
    except xmlrpc.client.Fault:
        # Si la sesión/uid se invalidó, reintenta una vez re-autenticando
        _uid = None
        return _models().execute_kw(ODOO_DB, _get_uid(), ODOO_API_KEY, model, method, args, kwargs or {})


def _clean(value: Any) -> Any:
    """Convierte tipos no serializables (bytes, datetime XML-RPC) a texto y poda binarios."""
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
    "Odoo Aromas de Té",
    instructions=(
        "Acceso completo al Odoo de Aromas de Té S.L. (aromasdete.odoo.com) vía XML-RPC. "
        "Los modelos habituales: sale.order (pedidos), account.move (facturas/asientos), "
        "res.partner (clientes/proveedores), product.template y product.product (productos), "
        "stock.picking (albaranes), account.bank.statement.line (líneas bancarias). "
        "La empresa principal es res.company id 1. Fechas en formato 'YYYY-MM-DD'. "
        "Antes de escribir en un modelo que no conozcas, consulta sus campos con odoo_campos. "
        "PRECAUCIÓN: es la base de datos de PRODUCCIÓN — confirma con el usuario antes de "
        "crear, modificar o ejecutar acciones con efecto contable."
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
    version = _common().version()
    uid = _get_uid()
    user = _execute("res.users", "read", [[uid]], {"fields": ["name", "login", "company_id"]})
    return _result({"version": version.get("server_version"), "usuario": user})


if __name__ == "__main__":
    path = os.environ["MCP_PATH"]
    if not path.startswith("/"):
        path = "/" + path
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
        path=path,
    )
