# Odette Panel (esqueleto fase 1)

Panel web para el bot **Odette**.

## Qué incluye ya
- Login con Discord (OAuth2)
- Lista de servidores donde eres admin / manage server
- Página por servidor (placeholder de config)
- Zona **Owner** (solo tu ID): premium local en JSON

## Qué falta (fase 2)
- Conectar interruptores reales con el bot en Wispbyte
- Sincronizar premium bot ↔ panel

---

## 1. Discord Developer Portal

1. [Discord Developer Portal](https://discord.com/developers/applications) → tu app del bot  
2. **OAuth2 → General**  
3. Copia **CLIENT ID** y **CLIENT SECRET**  
4. En **Redirects** añade (cuando tengas la URL de Render):

```text
https://NOMBRE-DE-TU-SERVICIO.onrender.com/callback
```

Scopes usados: `identify` `guilds`

---

## 2. Subir a GitHub

1. Crea repo `odette-panel`  
2. Sube **toda esta carpeta** (main.py, requirements.txt, templates/, static/, etc.)  
3. Commit  

---

## 3. Render

1. [render.com](https://render.com) → **New → Web Service**  
2. Conecta el repo `odette-panel`  
3. Ajustes:
   - **Runtime:** Python  
   - **Build Command:** `pip install -r requirements.txt`  
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`  
4. **Environment** (variables):

| Key | Valor |
|-----|--------|
| `DISCORD_CLIENT_ID` | tu client id |
| `DISCORD_CLIENT_SECRET` | tu client secret |
| `DISCORD_REDIRECT_URI` | `https://TU-SERVICIO.onrender.com/callback` |
| `BOT_OWNER_ID` | `545930956721356842` |
| `SECRET_KEY` | cualquier texto largo random |

5. Create Web Service → espera el deploy  
6. Abre la URL y prueba **Login con Discord**

---

## Local (opcional)

```bash
cd odette-panel
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# edita .env
uvicorn main:app --reload --port 8000
```

Redirect local de prueba:
`http://localhost:8000/callback` (añádelo también en Discord OAuth2 redirects)

---

## Estructura

```
odette-panel/
  main.py
  requirements.txt
  render.yaml
  .env.example
  README.md
  templates/
  static/
  data/          # se crea solo (premium JSON en el disco de Render)
```

**Nota free Render:** el disco puede borrarse en redeploys; el premium del panel es temporal hasta sincronizar con el bot.
