Odette — archivos actualizados (verify + seguridad)

PANEL
-----
artifacts/odette-panel/main.py
artifacts/odette-panel/templates/verify_result.html

Copia main.py a la raíz del repo del panel.
Copia verify_result.html a templates/

Env opcionales en Render:
  PUBLIC_BASE_URL=https://dette-panel-1.onrender.com
  VERIFY_MIN_ACCOUNT_DAYS=7
  IP_REPUTATION_KEY=  (clave proxycheck.io si quieres bloquear VPN)
  BLOCK_VPN=1
  PANEL_API_TOKEN=...

BOT
---
artifacts/odette-bot/PANEL_WEB_VERIFY.py  → pegar funciones en odette_bot.py
artifacts/odette-bot/odette_bot_CON_PANEL_RESTORE.py  → bot con backup/restore (antes)

.env bot:
  PANEL_API_URL=https://dette-panel-1.onrender.com
  PANEL_API_TOKEN=mismo_token
