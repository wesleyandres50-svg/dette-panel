# Odette — archivos generados

## Panel (Render)
- `odette-panel/main.py` → copiar a la raíz del repo del panel (sustituye el main.py actual)

También necesitas en el repo del panel:
- templates/guild.html
- templates/dashboard.html
- templates/owner.html
- templates/tickets.html
(usa los HTML que te pasé en el chat)

## Bot
- `odette-bot/PANEL_SYNC_BACKUP_RESTORE.py` → NO es el bot completo.
  Abre tu odette_bot.py y sustituye las funciones de panel sync por el contenido de este archivo.

### .env del bot
```
PANEL_API_URL=https://dette-panel-1.onrender.com
PANEL_API_TOKEN=yZLUyyjWWSuAYU_hB8u22U3-asSG85fIbP4mKJ_gVRQ
```

### Cómo funciona el restore
1. Guardas en el panel
2. Bot hace sync → guarda backup en data/panel_backup.json
3. Render free reinicia el panel y pierde JSON
4. Bot ve has_saved=false → POST restore → panel recupera la config
