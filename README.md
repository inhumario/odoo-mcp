# Inhumario MCP — Odoo para tu IA

Conecta el Odoo de cada cliente con su IA (Claude, ChatGPT o cualquier
aplicación compatible con el estándar MCP) mediante un servidor MCP remoto
multi-tenant con panel de autogestión.

- **Panel** (`app.py`): alta con código de invitación, credenciales de Odoo
  (verificadas al guardar), URL MCP privada por cliente e instrucciones de
  conexión. Claves de IA opcionales para el futuro chat integrado.
- **MCP** (`server.py`): 9 herramientas XML-RPC (buscar, contar, leer, crear,
  escribir, ejecutar genérico, campos, modelos, info) con las credenciales del
  tenant activo. Endpoint por cliente: `/t/<token>/mcp` (Streamable HTTP).

## Despliegue

EasyPanel, proyecto `travelia`, servicio `odoo-mcp`, build por Dockerfile.
Volumen en `/data` para SQLite. El push a `main` NO redespliega — disparar
`services.app.deployService`.

Env: `SECRET_KEY`, `ALTA_CODIGO`, `DB_PATH=/data/tenants.db`,
`BASE_URL=https://mcp.inhumario.com`, `PORT=8000` y opcionalmente
`MCP_PATH` + `ODOO_*` para la ruta legacy mono-tenant.

## Hoja de ruta (fase producto)

OAuth, herramientas por rol, cifrado de credenciales en reposo, panel de
administración, logs de uso por tenant, chat integrado con las claves de IA.
