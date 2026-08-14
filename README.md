# MCP de Odoo — Aromas de Té (piloto)

Servidor MCP remoto (Streamable HTTP) que expone el Odoo de Aromas por XML-RPC,
para usarlo como conector personalizado en Claude web y móvil.

- **Fase actual (piloto)**: sin restricciones — hereda los permisos del usuario de la
  API key (Mario, admin). Barrera de acceso: ruta secreta `MCP_PATH`.
- **Fase 2 (producto para clientes)**: OAuth + catálogo de herramientas por rol +
  panel de gestión. Ver `COMERCIAL.md` del proyecto Inhumario.

## Despliegue

EasyPanel (easypanel.aromasdete.com), proyecto `n8n`, servicio `odoo-mcp`,
build por Dockerfile desde este repo (GitHub `inhumario/odoo-mcp`).
El push a `main` NO redespliega solo — disparar con
`services.app.deployService` (ver memoria `deploy-easypanel`).

Variables de entorno del servicio: `ODOO_URL`, `ODOO_DB`, `ODOO_USER`,
`ODOO_API_KEY`, `MCP_PATH`, `PORT=8000`.

## Herramientas

`odoo_buscar`, `odoo_contar`, `odoo_leer`, `odoo_crear`, `odoo_escribir`,
`odoo_ejecutar` (genérico), `odoo_campos`, `odoo_modelos`, `odoo_info`.
