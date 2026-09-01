"""
Odette Panel — completo (sync + backup)
- OAuth, dashboard, config, tickets, premium guild+user
- API bot GET/POST config (restore bidireccional + force)
- Backups locales rotativos de configs y premium
- Verificación web: token 1 uso, edad cuenta, VPN opcional
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode
from collections import defaultdict

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as _JSONResponse
import hmac as _hmac

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(exist_ok=True)
AVATARS_DIR = DATA_DIR / "avatars"
AVATARS_DIR.mkdir(exist_ok=True)
PREMIUM_FILE = DATA_DIR / "premium_guilds.json"
CONFIG_FILE = DATA_DIR / "guild_configs.json"
VERIFY_TOKENS_FILE = DATA_DIR / "verify_tokens.json"
VERIFIED_USERS_FILE = DATA_DIR / "verified_users.json"


def _atomic_write(path: Path, text: str) -> None:
    """Escritura atómica para no corromper JSON si el proceso muere a medias."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _rotate_backup(src: Path, prefix: str, keep: int = 8) -> None:
    """Copia de seguridad rotativa en data/backups/."""
    if not src.is_file():
        return
    try:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dest = BACKUP_DIR / f"{prefix}_{ts}.json"
        shutil.copy2(src, dest)
        files = sorted(
            BACKUP_DIR.glob(f"{prefix}_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in files[keep:]:
            try:
                old.unlink()
            except Exception:
                pass
    except Exception as e:
        print(f"[backup] {prefix}: {e}")


DISCORD_CLIENT_ID = (os.getenv("DISCORD_CLIENT_ID") or "").strip()
DISCORD_CLIENT_SECRET = (os.getenv("DISCORD_CLIENT_SECRET") or "").strip()
DISCORD_REDIRECT_URI = (os.getenv("DISCORD_REDIRECT_URI") or "").strip()
BOT_OWNER_ID = int(os.getenv("BOT_OWNER_ID") or "545930956721356842")
SECRET_KEY = (os.getenv("SECRET_KEY") or secrets.token_hex(32)).strip()
PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL") or "").strip().rstrip("/")
VERIFY_MIN_ACCOUNT_DAYS = int(os.getenv("VERIFY_MIN_ACCOUNT_DAYS") or "7")
IP_REPUTATION_KEY = (os.getenv("IP_REPUTATION_KEY") or "").strip()
BLOCK_VPN = (os.getenv("BLOCK_VPN") or "1").strip() not in ("0", "false", "no")
BOT_TOKEN = (os.getenv("BOT_TOKEN") or os.getenv("DISCORD_BOT_TOKEN") or "").strip()
# Permisos invite bot (admin-ish: manage guild, roles, channels, messages, etc.)
BOT_INVITE_PERMISSIONS = (os.getenv("BOT_INVITE_PERMISSIONS") or "8").strip()  # 8 = Administrator
BOT_CLIENT_ID = (os.getenv("BOT_CLIENT_ID") or DISCORD_CLIENT_ID or "").strip()

API_BASE = "https://discord.com/api/v10"
OAUTH_AUTHORIZE = "https://discord.com/api/oauth2/authorize"
OAUTH_TOKEN = "https://discord.com/api/oauth2/token"

app = FastAPI(title="Odette Panel", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=60 * 60 * 24 * 7,
    same_site="lax",
    https_only=True,
    session_cookie="odette_session",
)

_rate_buckets: dict = defaultdict(list)
_RATE_WINDOW, _RATE_MAX, _RATE_API_MAX = 60.0, 90, 30


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client = request.client.host if request.client else "unknown"
        now = time.time()
        bucket = _rate_buckets[client]
        _rate_buckets[client] = [t for t in bucket if now - t < _RATE_WINDOW]
        limit = _RATE_API_MAX if request.url.path.startswith("/api/") else _RATE_MAX
        if len(_rate_buckets[client]) >= limit:
            return _JSONResponse({"error": "Demasiadas peticiones"}, status_code=429)
        _rate_buckets[client].append(now)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' https://cdn.discordapp.com data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response


app.add_middleware(SecurityHeadersMiddleware)

@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    """Evita página genérica sin log; no filtra secretos al cliente."""
    import traceback
    tb = traceback.format_exc()
    print(f"[UNHANDLED] {request.method} {request.url.path}: {exc}\n{tb}")
    if request.url.path.startswith("/api/"):
        return JSONResponse({"ok": False, "error": "internal_error"}, status_code=500)
    # Si falló el save, redirigir con error legible
    if request.method == "POST" and "/guild/" in request.url.path and request.url.path.rstrip("/").endswith("/save"):
        parts = request.url.path.strip("/").split("/")
        gid = parts[1] if len(parts) >= 2 else ""
        if gid.isdigit():
            return RedirectResponse(f"/guild/{gid}?err=save", status_code=303)
    return HTMLResponse(
        "<h1>Error interno</h1><p>Revisa los logs de Render (Console). "
        "Si guardabas config, recarga e intenta de nuevo.</p>",
        status_code=500,
    )



def _safe_token_eq(a: str, b: str) -> bool:
    try:
        return _hmac.compare_digest((a or "").encode(), (b or "").encode())
    except Exception:
        return False



def _form_str(form, name, default=""):
    try:
        v = form.get(name)
    except Exception:
        return default
    if v is None:
        return default
    if hasattr(v, "filename") and hasattr(v, "file"):
        return default
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.decode("utf-8", "ignore")
        except Exception:
            return default
    return str(v)


def _form_int(form, name, default=0):
    try:
        return int(_form_str(form, name, str(default)) or default)
    except Exception:
        return default

def _csrf_token(request: Request) -> str:
    tok = request.session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["_csrf"] = tok
    return tok


def _check_csrf(request: Request, form_token: str) -> bool:
    return _safe_token_eq(request.session.get("_csrf") or "", (form_token or "").strip())


def _clean_secret(val: str) -> str:
    v = (val or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return v


def _client_ip(request: Request) -> str:
    xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if xff:
        return xff
    return request.client.host if request.client else "unknown"


def _public_base() -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    if DISCORD_REDIRECT_URI:
        return DISCORD_REDIRECT_URI.replace("/callback", "").rstrip("/")
    return ""


_STATIC = BASE_DIR / "static"
_STATIC.mkdir(exist_ok=True)
app.mount("/media/avatars", StaticFiles(directory=str(DATA_DIR / "avatars")), name="avatars")
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

@app.on_event("startup")
async def _validate_templates():
    needed = ["base.html", "guild.html", "tickets.html", "bot_missing.html", "index.html"]
    tdir = BASE_DIR / "templates"
    print(f"[panel] templates dir: {tdir} exists={tdir.is_dir()}")
    for n in needed:
        p = tdir / n
        ok = p.is_file() and _template_is_html(n)
        print(f"[panel] template {n}: {'OK' if ok else 'MISSING/INVALID'}")
        if p.is_file() and not ok:
            head = p.read_text(encoding="utf-8", errors="ignore")[:80].replace("\n", " ")
            print(f"[panel]   head: {head!r}")


templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

def _template_is_html(name: str) -> bool:
    """Evita servir por error un .py u otro archivo como plantilla."""
    path = BASE_DIR / "templates" / name
    if not path.is_file():
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:200].lstrip()
    except Exception:
        return False
    # Debe ser Jinja/HTML, nunca código Python del bot
    if head.startswith("import ") or head.startswith("from "):
        return False
    if "{%" in head or "<!DOCTYPE" in head.upper() or "<html" in head.lower() or head.startswith("<"):
        return True
    return "{%" in path.read_text(encoding="utf-8", errors="ignore")[:2000]


def _safe_template_response(name: str, context: dict, status_code: int = 200):
    if not _template_is_html(name):
        print(f"[panel] PLANTILLA INVÁLIDA o ausente: templates/{name}")
        # Fallback HTML mínimo (no depende de archivos corruptos)
        guild = context.get("guild") or {}
        invite = context.get("invite_url") or bot_invite_url(str(guild.get("id") or ""))
        html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Odette Panel</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0b0e14;color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}}
.box{{max-width:480px;padding:28px;border-radius:16px;border:1px solid #1e293b;background:#111827;text-align:center}}
a.btn{{display:inline-block;margin:8px;padding:12px 20px;border-radius:999px;background:#5865F2;color:#fff;text-decoration:none;font-weight:700}}
a.sec{{background:transparent;border:1px solid #334155;color:#e2e8f0}}
p{{color:#94a3b8;line-height:1.5}}
</style></head><body><div class="box">
<h1>🦢 Plantilla no encontrada</h1>
<p>El archivo <code>templates/{name}</code> falta o está corrupto en el servidor
(a veces se sube el .py del bot por error).</p>
<p>Sube de nuevo <code>guild.html</code>, <code>base.html</code>, <code>tickets.html</code>
y <code>bot_missing.html</code> a la carpeta <code>templates/</code> en Render.</p>
<p><a class="btn" href="{invite}" target="_blank" rel="noopener">Invitar bot</a>
<a class="btn sec" href="/dashboard">Servidores</a></p>
</div></body></html>"""
        return HTMLResponse(html, status_code=500)
    return templates.TemplateResponse(name, context, status_code=status_code)


PANEL_API_TOKEN = _clean_secret(
    os.getenv("PANEL_API_TOKEN") or "yZLUyyjWWSuAYU_hB8u22U3-asSG85fIbP4mKJ_gVRQ"
)


# ───────────────────────── Premium ─────────────────────────

def _load_premium() -> dict:
    if not PREMIUM_FILE.exists():
        return {"guilds": {}, "users": {}}
    try:
        data = json.loads(PREMIUM_FILE.read_text(encoding="utf-8"))
        if isinstance(data.get("guilds"), list):
            data["guilds"] = {str(x): {"until": None, "label": "permanente"} for x in data["guilds"]}
        data.setdefault("guilds", {})
        data.setdefault("users", {})
        if not isinstance(data["guilds"], dict):
            data["guilds"] = {}
        if not isinstance(data["users"], dict):
            data["users"] = {}
        return data
    except Exception:
        return {"guilds": {}, "users": {}}


def _save_premium(data: dict) -> None:
    data.setdefault("guilds", {})
    data.setdefault("users", {})
    data.setdefault("free_profile", False)
    _rotate_backup(PREMIUM_FILE, "premium")
    _atomic_write(PREMIUM_FILE, json.dumps(data, indent=2, ensure_ascii=False))


def is_free_profile() -> bool:
    try:
        return bool((_load_premium() or {}).get("free_profile"))
    except Exception:
        return False


def set_free_profile(on: bool) -> bool:
    data = _load_premium()
    data["free_profile"] = bool(on)
    _save_premium(data)
    return bool(on)


def parse_duration(text: str):
    import re
    t = (text or "").strip().lower().replace(" ", "")
    if not t or t in ("perm", "permanente", "permanent", "forever", "siempre"):
        return True, None, "permanente", None
    if t.isdigit():
        n = int(t)
        if n <= 0 or n > 3650:
            return False, None, None, "Días inválidos"
        return True, n * 86400, f"{n}d", None
    if not re.fullmatch(r"(\d+[dhms])+", t):
        return False, None, None, "Formato inválido"
    total = 0
    for num, unit in re.findall(r"(\d+)([dhms])", t):
        n = int(num)
        total += n * (86400 if unit == "d" else 3600 if unit == "h" else 60 if unit == "m" else 1)
    if total <= 0:
        return False, None, None, "Duración inválida"
    d, r = divmod(total, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m and not d:
        parts.append(f"{m}m")
    return True, total, "".join(parts) or "0", None


def _premium_entry_status(entry):
    if not entry:
        return False, "Sin premium"
    until = entry.get("until")
    if until is None:
        return True, "Permanente"
    try:
        left = float(until) - time.time()
    except Exception:
        return False, "Sin premium"
    if left <= 0:
        return False, "Expirado"
    d, r = divmod(int(left), 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    if d >= 1:
        return True, f"{d} día{'s' if d != 1 else ''} {h}h restantes"
    if h >= 1:
        return True, f"{h}h {m}m restantes"
    return True, f"{max(1, m)}m restantes"


def is_premium(guild_id):
    data = _load_premium()
    gid = str(guild_id)
    entry = (data.get("guilds") or {}).get(gid)
    ok, status = _premium_entry_status(entry)
    if status == "expirado" and entry:
        (data.get("guilds") or {}).pop(gid, None)
        _save_premium(data)
    return ok, status


def is_user_premium(user_id):
    data = _load_premium()
    uid = str(user_id)
    entry = (data.get("users") or {}).get(uid)
    ok, status = _premium_entry_status(entry)
    if status == "expirado" and entry:
        (data.get("users") or {}).pop(uid, None)
        _save_premium(data)
    return ok, status


# ───────────────────────── Config ─────────────────────────


def _parse_level_roles(form) -> dict:
    """Compat module-level (guild_save tiene su propia copia local)."""
    roles = {}
    try:
        raw = ""
        if hasattr(form, "get"):
            raw = str(form.get("levels_roles_raw") or "").strip()
        if raw:
            for part in raw.replace(";", ",").split(","):
                part = part.strip()
                if ":" not in part:
                    continue
                a, b = part.split(":", 1)
                try:
                    roles[str(int(a.strip()))] = str(int(b.strip()))
                except Exception:
                    pass
    except Exception:
        pass
    return roles


def _default_config() -> dict:
    return {
        "anti_raid": {
            "enabled": False,
            "max_joins": 5,
            "window": 10,
            "account_age_days": 3,
            "action": "kick",
            "anti_bot": True,
            "anti_nuke": {
                "enabled": True,
                "max_channel_creates": 2,
                "max_channel_deletes": 2,
                "interval": 12,
                "action": "ban",
            },
        },
        "automod": {"enabled": False, "anti_invite": True, "action": "delete", "timeout_minutes": 10},
        "verify": {
            "enabled": False,
            "channel_id": "",
            "role_id": "",
            "message": "Bienvenido. Verifícate para acceder al servidor.",
            "min_account_days": VERIFY_MIN_ACCOUNT_DAYS,
            "block_vpn": True,
        },
        "logs": {
            "enabled": False,
            "channel_id": "",
            "events": {
                "message_delete": True,
                "message_edit": True,
                "message_bulk": True,
                "member_join": True,
                "member_leave": True,
                "member_ban": True,
                "member_unban": True,
                "nickname": True,
                "roles": True,
                "avatar": True,
                "username": True,
                "timeout": True,
                "voice": False,
                "channel_create": True,
                "channel_delete": True,
                "role_create": False,
                "role_delete": False,
                "invite_create": False,
                "invite_delete": False,
            },
        },
        "ia": {
            "enabled": False,
            "automod": True,
            "antiraid": True,
            "log_decisions": True,
            "strictness": "medium",
            "max_action": "timeout",
            "timeout_minutes": 10,
            "block_invites": True,
            "block_scams": True,
            "block_nsfw_sfw": False,
            "nick_filter": False,
            "auto_slowmode": False,
            "immune_admins": True,
            "immune_mods": True,
            "block_words": [],
            "allow_words": [],
            "custom_rules": [],
            "train_examples": [],
        },
        "welcome": {
            "enabled": False,
            "channel_id": "",
            "message": "¡Bienvenido {user} a **{server}**!",
        },
        "autorole": {
            "enabled": False,
            "role_id": "",
            "role_ids": [],
            "bot_role_id": "",
            "bot_role_ids": [],
        },
        "levels": {
            "enabled": False,
            "xp_per_message": 15,
            "xp_cooldown": 60,
            "channel_id": "",
            "message": "🎉 {user} subió al **nivel {level}** en **{server}**!",
            "use_embed": True,
            "image": "",
            "banner_url": "",
            "color": "#AFD7E6",
            "card_enabled": True,
            "stack_roles": True,
            "roles": {},
        },
        "booster": {
            "enabled": False,
            "channel_id": "",
            "message": "Gracias {user} por potenciar **{server}**!",
            "image_enabled": True,
            "custom_image": "",
        },
        "tickets": {
            "enabled": False,
            "channel_id": "",
            "category_id": "",
            "support_role_id": "",
            "panel_message": "¿Necesitas ayuda? Abre un ticket con el botón de abajo.",
            "open_message": "Ticket abierto por {user}. Describe tu problema y espera al staff.",
            "button_label": "Abrir ticket",
        },
        "starboard": {
            "enabled": False,
            "channel_id": "",
            "min_stars": 3,
            "emoji": "⭐",
            "self_star": False,
            "allow_images": True,
        },
        "embed_color": "#AFD7E6",
        "bot_profile": {
            "nick": None,
            "avatar_url": None,
            "footer": "Odette • El Lago de los Cisnes",
            "accent_emoji": "🦢",
            "custom_bio": None,
            "embed_color": "#AFD7E6",
            "status_note": None,
        },
        "nsfw": {"enabled": True},
        "alianzas": {
            "enabled": False,
            "channel_id": "",
            "auto_publish": True,
            "require_invite": True,
            "review_channel_id": "",
            "category_id": "",
            "support_role_id": "",
            "panel_title": "Solicitud de Alianza",
            "panel_description": "¿Quieres aliarte? Elige una opción y se abrirá un ticket.",
            "panel_image": "",
            "panel_color": "#AFD7E6",
            "button_label": "Solicitar alianza",
        },
        "raidmode": {"enabled": False},
        "antihoist": {"enabled": False},
        "quarantine": {
            "enabled": False,
            "role_id": "",
            "create_role": False,
            "role_name": "Cuarentena",
            "strip_roles": True,
            "log_channel_id": "",
        },
        "reports": {"enabled": False, "channel_id": ""},
        "suggest": {"enabled": False, "channel_id": ""},
        "modnotes": {"enabled": False},
        "watchlist": {"enabled": False},
        "reaction_roles": {"enabled": False},
        "selfroles": {
            "enabled": False,
            "channel_id": "",
            "modules_raw": "",
            "unique_in_module": True,
            "modules": [],
        },
        "invites": {
            "enabled": False,
            "channel_id": "",
            "message": "📨 {user} entró con la invitación de {inviter} (`{code}` · usos {uses})",
        },
        "sticky": {"enabled": False},
        "autoresponse": {"enabled": False},
        "afk": {"enabled": True},
        "snipe": {"enabled": True},
        "tempvc": {
            "enabled": False,
            "hub_channel_id": "",
            "category_id": "",
            "name_template": "🔊 {user}",
            "user_limit": 0,
            "create_text": True,
            "lock_on_owner_leave": True,
            "auto_delete": True,
        },
        "moderation": {
            "enabled": True,
            "staff_role_id": "",
            "immune_role_id": "",
            "sanction_channel_id": "",
        },
        "disabled_commands": [],
        "giveaways": {"enabled": True},
        "reminders": {"enabled": True},
        "economy": {
            "enabled": True,
            "daily_min": 100,
            "daily_max": 500,
            "weekly_min": 500,
            "weekly_max": 2000,
            "work_min": 50,
            "work_max": 250,
            "work_cooldown": 3600,
            "beg_min": 10,
            "beg_max": 80,
            "beg_cooldown": 600,
            "crime_min": 100,
            "crime_max": 400,
            "crime_fine": 150,
            "rob_percent": 15,
            "msg_daily": "Recibiste {amount} coins · racha {streak}",
            "msg_weekly": "Weekly: +{amount} coins",
            "msg_work": "Trabajaste y ganaste {amount} coins",
            "msg_beg_ok": "{text}",
            "msg_beg_fail": "{text}",
            "msg_crime_ok": "Crimen exitoso: +{amount} coins",
            "msg_crime_fail": "Te atraparon: -{amount} coins",
            "shop_roles": [],
            "shop_items": [],
            "log_channel_id": "",
            "shop_channel_id": "",
            "shop_message_id": "",
            "currency": "🪙",
            "start_cash": 0,
            "start_bank": 0,
            "max_cash": 0,
            "max_bank": 0,
            "slut_min": 20,
            "slut_max": 120,
            "slut_fine": 80,
            "slut_success": 0.55,
            "slut_cooldown": 900,
            "crime_success": 0.55,
            "rob_success": 0.45,
            "chat_money_min": 0,
            "chat_money_max": 0,
            "chat_money_cooldown": 60,
            "bet_min": 10,
            "bet_max": 0,
            "role_income": [],
            "msg_slut_ok": "💋 +{amount} {currency}",
            "msg_slut_fail": "😬 -{amount} {currency}",
        },
        "shop": {"enabled": False, "items": []},
        "reports": {"enabled": False, "channel_id": ""},
        "social": {
            "enabled": False,
            "channel_id": "",
            "youtube": "",
            "twitch": "",
            "youtube_on": True,
            "twitch_on": True,
            "message": "🔔 Nuevo en {platform}: **{title}**\n{url}",
            "last_youtube_id": "",
            "last_twitch_live": False,
        },
        "profiles": {"enabled": True},
        "marriage": {"enabled": True},
        "actions_sfw": {"enabled": True},
        "music": {"enabled": True},
        "fun": {"enabled": True},
    }


def _load_all_configs() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_all_configs(data: dict) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _rotate_backup(CONFIG_FILE, "configs")
        _atomic_write(CONFIG_FILE, json.dumps(data, indent=2, ensure_ascii=False))
        # Marca para que el bot pueda detectar cambios al instante (poll corto)
        _atomic_write(DATA_DIR / "config_version.txt", str(time.time()))
    except Exception as e:
        print(f"[config] write error: {e}")
        raise



async def _notify_bot_refresh(guild_id: str) -> None:
    """Avisa al bot al instante (BOT_CALLBACK_URL). Si no está, el bot usa poll /api/config-version."""
    import os as _os
    import httpx
    base = (_os.getenv("BOT_CALLBACK_URL") or "").strip().rstrip("/")
    if not base:
        return
    token = PANEL_API_TOKEN or ""
    url = f"{base}/internal/panel-refresh"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.post(
                url,
                json={"guild_id": str(guild_id)},
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            print(f"[bot-push] {guild_id} → {r.status_code}")
    except Exception as e:
        print(f"[bot-push] fail: {e}")


def get_guild_config(guild_id: str) -> dict:
    all_cfg = _load_all_configs()
    cfg = all_cfg.get(str(guild_id))
    if not cfg:
        return _default_config()
    base = _default_config()
    for key in base:
        if key not in cfg:
            cfg[key] = base[key]
        elif isinstance(base[key], dict) and isinstance(cfg.get(key), dict):
            for sub in base[key]:
                if sub not in cfg[key]:
                    cfg[key][sub] = base[key][sub]
    return cfg




def _parse_role_income(form) -> list:
    out = []
    for i in range(1, 16):
        rid = (form.get(f"role_income_id_{i}") or "").strip()
        if not rid:
            continue
        try:
            rid_i = int(rid)
            amount = int(str(form.get(f"role_income_amount_{i}") or "0").strip() or "0")
            hours = float(str(form.get(f"role_income_hours_{i}") or "24").strip() or "24")
        except Exception:
            continue
        out.append({"role_id": rid_i, "amount": max(0, amount), "hours": max(0.5, hours)})
    return out

def _parse_shop_roles(form) -> list:
    """Lee shop_role_id_N + shop_role_price_N + shop_role_name_N (hasta 20)."""
    roles = []
    for i in range(1, 21):
        rid = (form.get(f"shop_role_id_{i}") or "").strip()
        if not rid:
            continue
        try:
            rid_i = int(rid)
        except Exception:
            continue
        try:
            price = int(str(form.get(f"shop_role_price_{i}") or "0").strip() or "0")
        except Exception:
            price = 0
        name = (form.get(f"shop_role_name_{i}") or "").strip()[:80]
        roles.append({"role_id": rid_i, "price": max(0, price), "name": name or f"Rol {rid_i}"})
    return roles


def _parse_shop_items(form) -> list:
    items = []
    for i in range(1, 16):
        name = (form.get(f"shop_item_name_{i}") or "").strip()[:80]
        if not name:
            continue
        try:
            price = int(str(form.get(f"shop_item_price_{i}") or "0").strip() or "0")
        except Exception:
            price = 0
        items.append({"name": name, "price": max(0, price)})
    return items

def save_guild_config(guild_id: str, config: dict) -> None:
    all_cfg = _load_all_configs()
    all_cfg[str(guild_id)] = config
    _save_all_configs(all_cfg)
    # Lista de guilds tocados (el bot hace poll cada ~2s)
    try:
        dirty_path = DATA_DIR / "config_dirty.json"
        import json as _json
        dirty = {}
        if dirty_path.is_file():
            try:
                dirty = _json.loads(dirty_path.read_text(encoding="utf-8")) or {}
            except Exception:
                dirty = {}
        gids = list(dirty.get("guild_ids") or [])
        sid = str(guild_id)
        if sid not in gids:
            gids.append(sid)
        # mantener últimos 80
        dirty = {"guild_ids": gids[-80:], "ts": time.time()}
        dirty_path.write_text(_json.dumps(dirty), encoding="utf-8")
    except Exception as e:
        print(f"[config] dirty mark: {e}")
    # Push instantáneo al bot si hay BOT_CALLBACK_URL
    try:
        import asyncio as _asyncio
        try:
            loop = _asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_notify_bot_refresh(str(guild_id)))
            else:
                pass
        except Exception:
            pass
    except Exception:
        pass


def current_user(request: Request):
    return request.session.get("user")


def is_owner(request: Request) -> bool:
    u = current_user(request)
    return bool(u and int(u.get("id", 0)) == BOT_OWNER_ID)


# ───────────────────────── Verify helpers ─────────────────────────

def _load_verify_tokens() -> dict:
    if not VERIFY_TOKENS_FILE.exists():
        return {}
    try:
        return json.loads(VERIFY_TOKENS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_verify_tokens(data: dict) -> None:
    _atomic_write(VERIFY_TOKENS_FILE, json.dumps(data, indent=2, ensure_ascii=False))


def _load_verified_users() -> dict:
    if not VERIFIED_USERS_FILE.exists():
        return {}
    try:
        return json.loads(VERIFIED_USERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_verified_users(data: dict) -> None:
    _atomic_write(VERIFIED_USERS_FILE, json.dumps(data, indent=2, ensure_ascii=False))


def _discord_snowflake_created(user_id: str):
    try:
        uid = int(user_id)
        ms = (uid >> 22) + 1420070400000
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except Exception:
        return None


async def _ip_is_risky(ip: str) -> tuple[bool, str]:
    if not ip or ip in ("unknown", "127.0.0.1", "::1"):
        return False, "local"
    if not IP_REPUTATION_KEY:
        return False, "no_api"
    url = f"https://proxycheck.io/v2/{ip}?key={IP_REPUTATION_KEY}&vpn=1&risk=1"
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return False, "api_error"
            info = (r.json() or {}).get(ip) or {}
            proxy = str(info.get("proxy", "")).lower()
            typ = str(info.get("type", "")).lower()
            if proxy in ("yes", "1", "true") or typ in ("vpn", "proxy", "tor"):
                return True, typ or "proxy"
    except Exception:
        return False, "api_error"
    return False, "ok"



def bot_invite_url(guild_id: str | None = None) -> str:
    """Link de invitación del bot (con guild preseleccionado si se pasa)."""
    cid = BOT_CLIENT_ID or DISCORD_CLIENT_ID
    if not cid:
        return "https://discord.com/oauth2/authorize"
    params = {
        "client_id": cid,
        "permissions": BOT_INVITE_PERMISSIONS,
        "scope": "bot applications.commands",
    }
    if guild_id and str(guild_id).isdigit():
        params["guild_id"] = str(guild_id)
        params["disable_guild_select"] = "true"
    return f"{OAUTH_AUTHORIZE}?{urlencode(params)}"


async def check_bot_in_guild(guild_id: str) -> bool:
    """True si el bot está en el servidor. Si no hay token, no bloqueamos (True)."""
    if not guild_id or not str(guild_id).isdigit():
        return False
    if not BOT_TOKEN:
        # Sin token no podemos comprobar: no bloquear el panel
        return True
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"{API_BASE}/guilds/{guild_id}",
                headers={"Authorization": f"Bot {BOT_TOKEN}"},
            )
            # 200 = bot en el server; 403/404 = no está o sin acceso
            if r.status_code == 200:
                return True
            if r.status_code in (403, 404):
                return False
            # otros errores: no bloquear
            return True
    except Exception:
        return True


# ───────────────────────── Rutas web ─────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": current_user(request), "is_owner": is_owner(request)},
    )


@app.get("/login")
@app.post("/login")  # evita Method Not Allowed si un form reenvía POST aquí
async def login(request: Request):
    if not DISCORD_CLIENT_ID or not DISCORD_REDIRECT_URI:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "user": None, "is_owner": False, "error": "Faltan env Discord."},
            status_code=500,
        )
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": DISCORD_REDIRECT_URI,
        "scope": "identify guilds",
        "state": state,
        "prompt": "none",
    }
    return RedirectResponse(f"{OAUTH_AUTHORIZE}?{urlencode(params)}", status_code=303)


@app.get("/callback")
async def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return RedirectResponse("/?error=oauth", status_code=303)
    if not code or state != request.session.get("oauth_state"):
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "user": None, "is_owner": False, "error": "Login inválido."},
            status_code=400,
        )
    async with httpx.AsyncClient(timeout=20) as client:
        token_res = await client.post(
            OAUTH_TOKEN,
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_res.status_code != 200:
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "user": None, "is_owner": False, "error": "Token falló."},
                status_code=400,
            )
        access = token_res.json().get("access_token")
        me = await client.get(f"{API_BASE}/users/@me", headers={"Authorization": f"Bearer {access}"})
        guilds = await client.get(
            f"{API_BASE}/users/@me/guilds", headers={"Authorization": f"Bearer {access}"}
        )
    if me.status_code != 200:
        return RedirectResponse("/", status_code=303)
    user = me.json()
    request.session["user"] = {
        "id": str(user["id"]),
        "username": user.get("global_name") or user.get("username"),
        "avatar": user.get("avatar"),
    }
    glist = []
    if guilds.status_code == 200:
        for g in guilds.json():
            try:
                perms = int(g.get("permissions", 0))
            except Exception:
                perms = 0
            if (perms & 0x8) or (perms & 0x20):
                glist.append({"id": str(g["id"]), "name": g.get("name") or "Server", "icon": g.get("icon")})
    request.session["guilds"] = glist
    request.session.pop("oauth_state", None)
    nxt = request.session.pop("verify_next", None)
    if nxt:
        return RedirectResponse(nxt, status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    ok_u, st_u = is_user_premium(user["id"])
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "is_owner": is_owner(request),
            "guilds": request.session.get("guilds") or [],
            "user_premium": ok_u,
            "user_premium_status": st_u if ok_u else "Sin premium",
        },
    )


@app.get("/guild/{guild_id}", response_class=HTMLResponse)
async def guild_page(request: Request, guild_id: str):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not str(guild_id).isdigit():
        return RedirectResponse("/dashboard", status_code=303)
    guilds = request.session.get("guilds") or []
    guild = next((g for g in guilds if str(g["id"]) == str(guild_id)), None)
    if not guild and not is_owner(request):
        return RedirectResponse("/dashboard", status_code=303)
    if not guild:
        guild = {"id": guild_id, "name": f"Server {guild_id}", "icon": None}

    bot_present = await check_bot_in_guild(guild_id)
    invite = bot_invite_url(guild_id)
    if not bot_present:
        return _safe_template_response(
            "bot_missing.html",
            {
                "request": request,
                "user": user,
                "is_owner": is_owner(request),
                "guild": guild,
                "invite_url": invite,
            },
        )

    ok_g, st_g = is_premium(guild_id)
    ok_u, st_u = is_user_premium(user["id"])
    try:
        config = get_guild_config(guild_id)
    except Exception as e:
        print(f"[guild_page] config error {guild_id}: {e}")
        config = _default_config()
    return _safe_template_response(
        "guild.html",
        {
            "request": request,
            "user": user,
            "is_owner": is_owner(request),
            "guild": guild,
            "premium": ok_g or ok_u,
            "premium_status": st_g if ok_g else (st_u if ok_u else "no"),
            "config": config,
            "csrf_token": _csrf_token(request),
            "bot_present": True,
            "invite_url": invite,
            "free_profile": is_free_profile(),
        },
    )



@app.post("/guild/{guild_id}/bot-avatar")
async def guild_bot_avatar_upload(request: Request, guild_id: str):
    """Sube archivo de avatar del bot para este server (png/jpg/webp)."""
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    guilds = request.session.get("guilds") or []
    if not (any(str(g["id"]) == str(guild_id) for g in guilds) or is_owner(request)):
        return RedirectResponse("/dashboard", status_code=303)
    if not str(guild_id).isdigit():
        return RedirectResponse("/dashboard", status_code=303)
    form = await request.form()
    if not _check_csrf(request, str(form.get("csrf_token") or "")):
        return RedirectResponse(f"/guild/{guild_id}?err=csrf", status_code=303)
    ok_g, _ = is_premium(guild_id)
    ok_u, _ = is_user_premium(user["id"])
    free_on = is_free_profile()
    if not (ok_g or ok_u or free_on or is_owner(request)):
        return RedirectResponse(f"/guild/{guild_id}?err=premium", status_code=303)
    file = form.get("bot_avatar_file")
    if file is None or not hasattr(file, "read"):
        return RedirectResponse(f"/guild/{guild_id}?err=avatar", status_code=303)
    content = await file.read()
    if not content or len(content) > 8_000_000:
        return RedirectResponse(f"/guild/{guild_id}?err=avatar", status_code=303)
    # guardar como png/jpg segun content-type
    fname = (getattr(file, "filename", None) or "avatar.png").lower()
    ext = "png"
    if fname.endswith(".jpg") or fname.endswith(".jpeg"):
        ext = "jpg"
    elif fname.endswith(".webp"):
        ext = "webp"
    AVATARS_DIR.mkdir(exist_ok=True)
    out = AVATARS_DIR / f"{guild_id}.{ext}"
    # limpia otros formatos viejos
    for old in AVATARS_DIR.glob(f"{guild_id}.*"):
        try:
            old.unlink()
        except Exception:
            pass
    out.write_bytes(content)
    # URL publica del panel
    base = (os.getenv("PUBLIC_BASE_URL") or str(request.base_url)).rstrip("/")
    public_url = f"{base}/media/avatars/{guild_id}.{ext}"
    cfg = get_guild_config(guild_id)
    bp = dict(cfg.get("bot_profile") or {})
    bp["avatar_url"] = public_url
    cfg["bot_profile"] = bp
    cfg["_panel_saved"] = True
    cfg["_saved_at"] = time.time()
    save_guild_config(guild_id, cfg)
    return RedirectResponse(f"/guild/{guild_id}?ok=1", status_code=303)



def _parse_shop_items(raw) -> list:
    """Parsea items de tienda desde texto del formulario.
    Formatos aceptados (uno por línea):
      nombre | precio | descripción
      nombre;precio;descripción
    O JSON: [{"name":"...","price":100,"description":"..."}]
    """
    if raw is None:
        return []
    if hasattr(raw, "filename") and hasattr(raw, "file"):
        return []
    text = str(raw).strip()
    if not text:
        return []
    # JSON
    if text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                out = []
                for it in data[:50]:
                    if not isinstance(it, dict):
                        continue
                    name = str(it.get("name") or it.get("nombre") or "").strip()[:80]
                    if not name:
                        continue
                    try:
                        price = int(it.get("price") or it.get("precio") or 0)
                    except Exception:
                        price = 0
                    desc = str(it.get("description") or it.get("desc") or "").strip()[:200]
                    out.append({"name": name, "price": max(0, price), "description": desc})
                return out
        except Exception:
            pass
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            parts = [p.strip() for p in line.split("|")]
        elif ";" in line:
            parts = [p.strip() for p in line.split(";")]
        elif "," in line:
            parts = [p.strip() for p in line.split(",", 2)]
        else:
            parts = [line]
        name = (parts[0] if parts else "").strip()[:80]
        if not name:
            continue
        try:
            price = int(parts[1]) if len(parts) > 1 else 0
        except Exception:
            price = 0
        desc = (parts[2] if len(parts) > 2 else "").strip()[:200]
        out.append({"name": name, "price": max(0, price), "description": desc})
        if len(out) >= 50:
            break
    return out


@app.post("/guild/{guild_id}/save")
async def guild_save(request: Request, guild_id: str):
    from fastapi.responses import JSONResponse

    def _wants_json() -> bool:
        accept = (request.headers.get("accept") or "").lower()
        xrw = (request.headers.get("x-requested-with") or "").lower()
        return (
            "application/json" in accept
            or xrw == "xmlhttprequest"
            or request.query_params.get("ajax") == "1"
        )

    def _err(code: str, status: int = 400):
        if _wants_json():
            return JSONResponse({"ok": False, "error": code}, status_code=status)
        if code == "login":
            return RedirectResponse("/login", status_code=303)
        if code == "dashboard":
            return RedirectResponse("/dashboard", status_code=303)
        return RedirectResponse(f"/guild/{guild_id}?err={code}", status_code=303)

    user = current_user(request)
    if not user:
        return _err("login", 401)
    guilds = request.session.get("guilds") or []
    if not (any(str(g["id"]) == str(guild_id) for g in guilds) or is_owner(request)):
        return _err("dashboard", 403)
    try:
        form = await request.form()
    except Exception as e:
        print(f"[guild_save] form error: {e}")
        return _err("form")
    token = _form_str(form, "csrf_token").strip()
    if not token or not _check_csrf(request, token):
        print(f"[guild_save] csrf fail guild={guild_id} token_len={len(token)}")
        return _err("csrf", 403)
    if not str(guild_id).isdigit():
        return _err("dashboard", 400)

    def _s(name, default=""):
        return _form_str(form, name, default)

    def _int(name, default=0):
        return _form_int(form, name, default)

    def _parse_level_roles(form_obj) -> dict:
        """roles: levels_roles_raw '5:ID,10:ID' o levels_role_level_N + levels_role_id_N."""
        roles = {}
        raw = (_form_str(form_obj, "levels_roles_raw") or "").strip()
        if raw:
            for part in raw.replace(";", ",").split(","):
                part = part.strip()
                if not part or ":" not in part:
                    continue
                a, b = part.split(":", 1)
                try:
                    roles[str(int(a.strip()))] = str(int(b.strip()))
                except Exception:
                    pass
        for i in range(1, 21):
            lv = (_form_str(form_obj, f"levels_role_level_{i}") or "").strip()
            rid = (_form_str(form_obj, f"levels_role_id_{i}") or "").strip()
            if not lv or not rid:
                continue
            try:
                roles[str(int(lv))] = str(int(rid))
            except Exception:
                pass
        return roles

    try:
        prev = get_guild_config(guild_id)
    except Exception as e:
        print(f"[guild_save] get_guild_config error: {e}")
        prev = _default_config()
    prev_tickets = prev.get("tickets") or {}

    config = {
        "anti_raid": {
            "enabled": form.get("anti_raid_enabled") == "on",
            "max_joins": max(1, min(_int("anti_raid_max_joins", 5), 50)),
            "window": max(5, min(_int("anti_raid_window", 10), 120)),
            "account_age_days": max(0, min(_int("anti_raid_account_age", 3), 365)),
            "action": (form.get("anti_raid_action") or "kick").lower()[:16],
            "anti_bot": form.get("anti_raid_anti_bot") == "on",
            "anti_nuke": {
                "enabled": form.get("anti_raid_nuke_enabled") == "on",
                "max_channel_creates": max(1, min(_int("anti_raid_nuke_channels", 2), 20)),
                "max_channel_deletes": max(1, min(_int("anti_raid_nuke_channels", 2), 20)),
                "interval": max(5, min(_int("anti_raid_nuke_interval", 12), 60)),
                "action": (form.get("anti_raid_nuke_action") or "ban").lower()[:16],
            },
        },
        "automod": {
            "enabled": form.get("automod_enabled") == "on",
            "anti_invite": form.get("automod_anti_invite") == "on",
            "action": (form.get("automod_action") or "delete").strip().lower()[:16],
            "timeout_minutes": max(1, min(_int("automod_timeout", 10), 10080)),
        },
        "verify": {
            "enabled": form.get("verify_enabled") == "on",
            "channel_id": _s("verify_channel").strip(),
            "role_id": _s("verify_role").strip(),
            "message": _s("verify_message").strip()[:1000],
            "min_account_days": max(0, min(_int("verify_min_days", VERIFY_MIN_ACCOUNT_DAYS), 365)),
            "block_vpn": form.get("verify_block_vpn") == "on",
        },
        "logs": {
            "enabled": form.get("logs_enabled") == "on",
            "channel_id": _s("logs_channel").strip(),
            "events": {
                "message_delete": form.get("log_ev_message_delete") == "on",
                "message_edit": form.get("log_ev_message_edit") == "on",
                "message_bulk": form.get("log_ev_message_bulk") == "on",
                "member_join": form.get("log_ev_member_join") == "on",
                "member_leave": form.get("log_ev_member_leave") == "on",
                "member_ban": form.get("log_ev_member_ban") == "on",
                "member_unban": form.get("log_ev_member_unban") == "on",
                "nickname": form.get("log_ev_nickname") == "on",
                "roles": form.get("log_ev_roles") == "on",
                "avatar": form.get("log_ev_avatar") == "on",
                "username": form.get("log_ev_username") == "on",
                "timeout": form.get("log_ev_timeout") == "on",
                "voice": form.get("log_ev_voice") == "on",
                "channel_create": form.get("log_ev_channel_create") == "on",
                "channel_delete": form.get("log_ev_channel_delete") == "on",
                "role_create": form.get("log_ev_role_create") == "on",
                "role_delete": form.get("log_ev_role_delete") == "on",
                "invite_create": form.get("log_ev_invite_create") == "on",
                "invite_delete": form.get("log_ev_invite_delete") == "on",
            },
        },
        "ia": {
            "enabled": form.get("ia_enabled") == "on",
            "automod": form.get("ia_automod") == "on",
            "antiraid": form.get("ia_antiraid") == "on",
            "log_decisions": form.get("ia_log_decisions") == "on",
            "strictness": (form.get("ia_strictness") or "medium").strip().lower()[:16],
            "max_action": (form.get("ia_max_action") or "timeout").strip().lower()[:16],
            "timeout_minutes": max(1, min(_int("ia_timeout_minutes", 10), 10080)),
            "block_invites": form.get("ia_block_invites") == "on",
            "block_scams": form.get("ia_block_scams") == "on",
            "block_nsfw_sfw": form.get("ia_block_nsfw_sfw") == "on",
            "nick_filter": form.get("ia_nick_filter") == "on",
            "auto_slowmode": form.get("ia_auto_slowmode") == "on",
            "immune_admins": form.get("ia_immune_admins") == "on",
            "immune_mods": form.get("ia_immune_mods") == "on",
            "block_words": [x.strip() for x in (form.get("ia_block_words") or "").splitlines() if x.strip()][:80],
            "allow_words": [x.strip() for x in (form.get("ia_allow_words") or "").splitlines() if x.strip()][:80],
            "custom_rules": [x.strip() for x in (form.get("ia_custom_rules") or "").splitlines() if x.strip()][:40],
            "train_examples": [x.strip() for x in (form.get("ia_train_examples") or "").splitlines() if x.strip()][:60],
        },
        "welcome": {
            "enabled": form.get("welcome_enabled") == "on",
            "channel_id": _s("welcome_channel").strip(),
            "message": _s("welcome_message").strip()[:1500],
            "image": _s("welcome_image").strip()[:500],
            "banner_url": _s("welcome_banner").strip()[:500],
            "card_enabled": form.get("welcome_card_enabled") == "on",
            "title": _s("welcome_title", "¡Bienvenido/a!").strip()[:120],
        },
        "autorole": {
            "enabled": form.get("autorole_enabled") == "on",
            "role_id": _s("autorole_role").strip(),
            "role_ids": [x.strip() for x in (_s("autorole_roles") or "").split(",") if x.strip()][:15],
            "bot_role_id": _s("autorole_bot_role").strip(),
            "bot_role_ids": [x.strip() for x in (_s("autorole_bot_roles") or "").split(",") if x.strip()][:10],
        },
        "levels": {
            "enabled": form.get("levels_enabled") == "on",
            "xp_per_message": max(1, min(_int("levels_xp_per_message", 15), 100)),
            "xp_cooldown": max(5, min(_int("levels_xp_cooldown", 60), 600)),
            "channel_id": _s("levels_channel").strip(),
            "message": _s("levels_message", "🎉 {user} subió al **nivel {level}** en **{server}**!")[:300],
            "use_embed": form.get("levels_use_embed") == "on",
            "image": _s("levels_image").strip(),
            "banner_url": _s("levels_banner").strip(),
            "color": _s("levels_color", "#AFD7E6").strip() or "#AFD7E6",
            "card_enabled": form.get("levels_card_enabled") == "on",
            "stack_roles": form.get("levels_stack_roles") == "on",
            "top_roles_enabled": form.get("levels_top_roles_enabled") == "on",
            "top1_role_id": _s("levels_top1_role").strip(),
            "top10_role_id": _s("levels_top10_role").strip(),
            "roles": _parse_level_roles(form),
        },
        "booster": {
            "enabled": form.get("booster_enabled") == "on",
            "channel_id": _s("booster_channel").strip(),
            "message": _s("booster_message").strip()[:1500],
            "image_enabled": form.get("booster_image_enabled") == "on",
            "custom_image": _s("booster_custom_image").strip()[:500],
        },
        "tickets": {**prev_tickets, "enabled": form.get("tickets_enabled") == "on"},
        "starboard": {
            "enabled": form.get("starboard_enabled") == "on",
            "channel_id": _s("starboard_channel").strip(),
            "min_stars": max(1, min(_int("starboard_min", 3), 25)),
            "emoji": (_s("starboard_emoji") or "⭐").strip()[:64] or "⭐",
            "self_star": form.get("starboard_self_star") == "on",
            "allow_images": form.get("starboard_allow_images") == "on",
        },
        "nsfw": {"enabled": form.get("nsfw_enabled") == "on"},
        "alianzas": {
            "enabled": form.get("alianzas_enabled") == "on",
            "channel_id": _s("alianzas_channel").strip(),
            "auto_publish": form.get("alianzas_auto_publish") == "on",
            "require_invite": form.get("alianzas_require_invite") == "on",
            "review_channel_id": _s("alianzas_review_channel").strip(),
            "category_id": _s("alianzas_category").strip(),
            "support_role_id": _s("alianzas_support_role").strip(),
            "panel_title": _s("alianzas_panel_title", "Solicitud de Alianza")[:120],
            "panel_description": _s("alianzas_panel_description")[:500],
            "panel_image": _s("alianzas_panel_image").strip(),
            "panel_color": _s("alianzas_panel_color", "#AFD7E6").strip() or "#AFD7E6",
            "button_label": _s("alianzas_button_label", "Solicitar alianza")[:80],
        },
        "raidmode": {"enabled": form.get("raidmode_enabled") == "on"},
        "antihoist": {"enabled": form.get("antihoist_enabled") == "on"},
        "quarantine": {
            "enabled": form.get("quarantine_enabled") == "on",
            "role_id": _s("quarantine_role").strip(),
            "create_role": form.get("quarantine_create_role") == "on",
            "role_name": (form.get("quarantine_role_name") or "Cuarentena").strip()[:80] or "Cuarentena",
            "strip_roles": form.get("quarantine_strip_roles") == "on",
            "log_channel_id": _s("quarantine_log_channel").strip(),
        },
        "reports": {
            "enabled": form.get("reports_enabled") == "on",
            "channel_id": _s("reports_channel").strip(),
        },
        "suggest": {
            "enabled": form.get("suggest_enabled") == "on",
            "channel_id": _s("suggest_channel").strip(),
        },
        "modnotes": {"enabled": form.get("modnotes_enabled") == "on"},
        "watchlist": {"enabled": form.get("watchlist_enabled") == "on"},
                "reaction_roles": {"enabled": form.get("reaction_roles_enabled") == "on" or form.get("selfroles_enabled") == "on"},
        "selfroles": {
            "enabled": form.get("selfroles_enabled") == "on",
            "channel_id": _s("selfroles_channel").strip(),
            "modules_raw": _s("selfroles_modules")[:8000],
            "unique_in_module": form.get("selfroles_unique") == "on",
            "modules": [],  # rellenado abajo
        },
        "invites": {
            "enabled": form.get("invites_enabled") == "on",
            "channel_id": _s("invites_channel").strip(),
            "message": _s("invites_message", "📨 {user} entró con la invitación de {inviter} (`{code}` · usos {uses})").strip()[:1500],
        },
        "anti_raid_whitelist": {
            "users": [x.strip() for x in (_s("ar_wl_users") or "").split(",") if x.strip()][:50],
            "roles": [x.strip() for x in (_s("ar_wl_roles") or "").split(",") if x.strip()][:30],
        },
        "sticky": {"enabled": form.get("sticky_enabled") == "on"},
        "autoresponse": {"enabled": form.get("autoresponse_enabled") == "on"},
        "afk": {"enabled": form.get("afk_enabled") == "on"},
        "snipe": {"enabled": form.get("snipe_enabled") == "on"},
        "tempvc": {
            "enabled": form.get("tempvc_enabled") == "on",
            "hub_channel_id": _s("tempvc_hub").strip(),
            "category_id": _s("tempvc_category").strip(),
            "name_template": (_s("tempvc_name") or "🔊 {user}").strip()[:80],
            "user_limit": max(0, min(_int("tempvc_limit", 0), 99)),
            "create_text": form.get("tempvc_text") == "on",
            "lock_on_owner_leave": form.get("tempvc_lock_empty") == "on",
            "auto_delete": form.get("tempvc_auto_delete") == "on",
        },
        "moderation": {
            "enabled": form.get("moderation_enabled") == "on",
            "staff_role_id": _s("mod_staff_role").strip(),
            "immune_role_id": _s("mod_immune_role").strip(),
            "sanction_channel_id": _s("mod_sanction_channel").strip(),
        },
        "disabled_commands": [
            x.strip().lower()
            for x in (_s("disabled_commands") or "").replace(",", "\n").splitlines()
            if x.strip()
        ][:80],
        "giveaways": {"enabled": form.get("giveaways_enabled") == "on"},
        "reminders": {"enabled": form.get("reminders_enabled") == "on"},
        "economy": {
            "enabled": form.get("economy_enabled") == "on",
            "daily_min": max(0, _int("economy_daily_min", 100)),
            "daily_max": max(0, _int("economy_daily_max", 500)),
            "weekly_min": max(0, _int("economy_weekly_min", 500)),
            "weekly_max": max(0, _int("economy_weekly_max", 2000)),
            "work_min": max(0, _int("economy_work_min", 50)),
            "work_max": max(0, _int("economy_work_max", 250)),
            "work_cooldown": max(60, min(_int("economy_work_cd", 3600), 86400)),
            "beg_min": max(0, _int("economy_beg_min", 10)),
            "beg_max": max(0, _int("economy_beg_max", 80)),
            "beg_cooldown": max(30, min(_int("economy_beg_cd", 600), 86400)),
            "crime_min": max(0, _int("economy_crime_min", 100)),
            "crime_max": max(0, _int("economy_crime_max", 400)),
            "crime_fine": max(0, _int("economy_crime_fine", 150)),
            "rob_percent": max(1, min(_int("economy_rob_percent", 15), 50)),
            "msg_daily": _s("economy_msg_daily", "Recibiste {amount} coins · racha {streak}")[:200],
            "msg_weekly": _s("economy_msg_weekly", "Weekly: +{amount} coins")[:200],
            "msg_work": _s("economy_msg_work", "Trabajaste y ganaste {amount} coins")[:200],
            "msg_beg_ok": _s("economy_msg_beg_ok", "{text}")[:200],
            "msg_beg_fail": _s("economy_msg_beg_fail", "{text}")[:200],
            "msg_crime_ok": _s("economy_msg_crime_ok", "Crimen exitoso: +{amount} coins")[:200],
            "msg_crime_fail": _s("economy_msg_crime_fail", "Te atraparon: -{amount} coins")[:200],
            "log_channel_id": _s("economy_log_channel").strip(),
            "shop_channel_id": _s("economy_shop_channel").strip(),
            "shop_message_id": _s("economy_shop_message").strip(),
            "currency": (_s("economy_currency") or "🪙").strip()[:16] or "🪙",
            "start_cash": max(0, _int("economy_start_cash", 0)),
            "start_bank": max(0, _int("economy_start_bank", 0)),
            "max_cash": max(0, _int("economy_max_cash", 0)),
            "max_bank": max(0, _int("economy_max_bank", 0)),
            "slut_min": max(0, _int("economy_slut_min", 20)),
            "slut_max": max(0, _int("economy_slut_max", 120)),
            "slut_fine": max(0, _int("economy_slut_fine", 80)),
            "slut_success": max(0.05, min(float(form.get("economy_slut_success") or 0.55), 0.95)),
            "slut_cooldown": max(60, min(_int("economy_slut_cd", 900), 86400)),
            "crime_success": max(0.05, min(float(form.get("economy_crime_success") or 0.55), 0.95)),
            "rob_success": max(0.05, min(float(form.get("economy_rob_success") or 0.45), 0.95)),
            "chat_money_min": max(0, _int("economy_chat_min", 0)),
            "chat_money_max": max(0, _int("economy_chat_max", 0)),
            "chat_money_cooldown": max(10, min(_int("economy_chat_cd", 60), 3600)),
            "bet_min": max(1, _int("economy_bet_min", 10)),
            "bet_max": max(0, _int("economy_bet_max", 0)),
            "role_income": _parse_role_income(form),
            "msg_slut_ok": _s("economy_msg_slut_ok", "💋 +{amount} {currency}")[:200],
            "msg_slut_fail": _s("economy_msg_slut_fail", "😬 -{amount} {currency}")[:200],
            "shop_roles": _parse_shop_roles(form),
            "shop_items": _parse_shop_items(form),
        },
        "social": {
            "enabled": form.get("social_enabled") == "on",
            "channel_id": _s("social_channel_id").strip()[:32],
            "youtube": _s("social_youtube").strip()[:120],
            "twitch": _s("social_twitch").strip()[:64],
            "youtube_on": form.get("social_youtube_on") == "on",
            "twitch_on": form.get("social_twitch_on") == "on",
            "message": _s("social_message", "🔔 Nuevo en {platform}: **{title}**\n{url}")[:300],
        },
        "reports": {
            "enabled": form.get("reports_enabled") == "on",
            "channel_id": _s("reports_channel_id").strip()[:32],
        },
        "shop": {
            "enabled": form.get("shop_enabled") == "on",
            "items": _parse_shop_items(_form_str(form, "shop_items")),
        },
        "profiles": {"enabled": form.get("profiles_enabled") == "on"},
        "marriage": {"enabled": form.get("marriage_enabled") == "on"},
        "actions_sfw": {"enabled": form.get("actions_sfw_enabled") == "on"},
        "music": {"enabled": form.get("music_enabled") == "on"},
        "fun": {"enabled": form.get("fun_enabled") == "on"},
    }
    # Color de embeds del servidor (#RRGGBB)
    _raw_color = (form.get("embed_color") or "#AFD7E6").strip()
    if not _raw_color.startswith("#"):
        _raw_color = "#" + _raw_color
    if len(_raw_color) != 7:
        _raw_color = "#AFD7E6"
    try:
        int(_raw_color[1:], 16)
    except Exception:
        _raw_color = "#AFD7E6"
    config["embed_color"] = _raw_color.upper()

    # Free profile global (solo dueña)
    if is_owner(request):
        set_free_profile(form.get("free_profile") == "on")

    # Perfil del bot por servidor (estilo MEE6)
    ok_g, _ = is_premium(guild_id)
    ok_u, _ = is_user_premium(user["id"])
    free_on = is_free_profile()
    can_profile = bool(ok_g or ok_u or free_on or is_owner(request))
    prev_bp = (prev.get("bot_profile") or {}) if isinstance(prev.get("bot_profile"), dict) else {}
    if can_profile:
        _bn = _s("bot_nick").strip()
        _bf = _s("bot_footer").strip()[:100]
        _be = (form.get("bot_emoji") or "🦢").strip()[:8] or "🦢"
        _bb = _s("bot_bio").strip()[:200]
        _bc = (form.get("bot_embed_color") or config.get("embed_color") or "#AFD7E6").strip()
        if not _bc.startswith("#"):
            _bc = "#" + _bc
        if len(_bc) != 7:
            _bc = config.get("embed_color") or "#AFD7E6"
        try:
            int(_bc[1:], 16)
        except Exception:
            _bc = "#AFD7E6"
        _ba = _s("bot_avatar_url").strip()[:500]
        config["bot_profile"] = {
            "nick": _bn[:32] if _bn else None,
            "avatar_url": _ba if _ba else None,
            "footer": _bf or "Odette • El Lago de los Cisnes",
            "accent_emoji": _be,
            "custom_bio": _bb or None,
            "embed_color": _bc.upper(),
            "status_note": prev_bp.get("status_note"),
        }
    else:
        config["bot_profile"] = prev_bp or {
            "nick": None,
            "avatar_url": None,
            "footer": "Odette • El Lago de los Cisnes",
            "accent_emoji": "🦢",
            "custom_bio": None,
            "embed_color": "#AFD7E6",
            "status_note": None,
        }

    if not (ok_g or ok_u):
        config["ia"]["enabled"] = False
    # Parse selfroles modules from raw text
    try:
        raw = (config.get("selfroles") or {}).get("modules_raw") or ""
        modules = []
        cur = None
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("##"):
                if cur and cur.get("roles"):
                    modules.append(cur)
                cur = {"name": line.lstrip("#").strip()[:80], "roles": []}
            elif cur is not None and ":" in line:
                lab, rid = line.split(":", 1)
                rid = rid.strip()
                if rid.isdigit():
                    cur["roles"].append({"label": lab.strip()[:40], "role_id": rid})
        if cur and cur.get("roles"):
            modules.append(cur)
        config.setdefault("selfroles", {})["modules"] = modules[:20]
    except Exception as e:
        print(f"[selfroles parse] {e}")

    config["_panel_saved"] = True
    config["_saved_at"] = time.time()
    try:
        save_guild_config(guild_id, config)
    except Exception as e:
        print(f"[guild_save] save error {guild_id}: {e}")
        if _wants_json():
            return JSONResponse({"ok": False, "error": "save"}, status_code=500)
        return RedirectResponse(f"/guild/{guild_id}?err=save", status_code=303)
    print(f"[guild_save] OK guild={guild_id}")
    # Sync agresiva: version + dirty + push callback
    try:
        _atomic_write(DATA_DIR / "config_version.txt", str(time.time()))
        dirty_path = DATA_DIR / "config_dirty.json"
        import json as _json
        dirty = {"guild_ids": [str(guild_id)], "ts": time.time()}
        dirty_path.write_text(_json.dumps(dirty), encoding="utf-8")
    except Exception as e:
        print(f"[guild_save] dirty: {e}")
    try:
        await _notify_bot_refresh(str(guild_id))
    except Exception as e:
        print(f"[guild_save] bot-push: {e}")
    if _wants_json():
        return JSONResponse({
            "ok": True,
            "guild_id": str(guild_id),
            "saved_at": config.get("_saved_at"),
            "message": "Cambios guardados",
        })
    return RedirectResponse(f"/guild/{guild_id}?ok=1", status_code=303)


@app.get("/guild/{guild_id}/tickets", response_class=HTMLResponse)
async def tickets_page(request: Request, guild_id: str):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not str(guild_id).isdigit():
        return RedirectResponse("/dashboard", status_code=303)
    guilds = request.session.get("guilds") or []
    guild = next((g for g in guilds if str(g["id"]) == str(guild_id)), None)
    if not guild and not is_owner(request):
        return RedirectResponse("/dashboard", status_code=303)
    if not guild:
        guild = {"id": guild_id, "name": f"Server {guild_id}", "icon": None}
    bot_present = await check_bot_in_guild(guild_id)
    if not bot_present:
        return _safe_template_response(
            "bot_missing.html",
            {
                "request": request,
                "user": user,
                "is_owner": is_owner(request),
                "guild": guild,
                "invite_url": bot_invite_url(guild_id),
            },
        )
    try:
        config = get_guild_config(guild_id)
    except Exception:
        config = _default_config()
    return _safe_template_response(
        "tickets.html",
        {
            "request": request,
            "user": user,
            "guild": guild,
            "config": config,
            "csrf_token": _csrf_token(request),
        },
    )


@app.post("/guild/{guild_id}/tickets/save")
async def tickets_save(request: Request, guild_id: str):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    guilds = request.session.get("guilds") or []
    if not (any(str(g["id"]) == str(guild_id) for g in guilds) or is_owner(request)):
        return RedirectResponse("/dashboard", status_code=303)
    form = await request.form()
    if not _check_csrf(request, str(form.get("csrf_token") or "")):
        return RedirectResponse(f"/guild/{guild_id}/tickets?err=csrf", status_code=303)
    if not str(guild_id).isdigit():
        return RedirectResponse("/dashboard", status_code=303)

    def _s(name, default=""):
        return _form_str(form, name, default)

    def _int(name, default=0):
        return _form_int(form, name, default)

    config = get_guild_config(guild_id)
    options = []
    for i in range(25):
        label = (form.get(f"tickets_opt_{i}_label") or "").strip()[:100]
        if not label:
            continue
        value = (form.get(f"tickets_opt_{i}_value") or "").strip()[:50]
        if not value:
            value = "".join(c for c in label.lower().replace(" ", "-") if c.isalnum() or c in "-_")[:50] or f"opt{i}"
        options.append({
            "label": label,
            "emoji": (form.get(f"tickets_opt_{i}_emoji") or "🎫").strip()[:8] or "🎫",
            "description": (form.get(f"tickets_opt_{i}_desc") or "").strip()[:100],
            "value": value,
        })
    if not options:
        options = [
            {"label": "Soporte", "emoji": "🛠️", "description": "Ayuda general", "value": "soporte"},
            {"label": "Reporte", "emoji": "🚨", "description": "Reportar usuario", "value": "reporte"},
        ]
    panel_desc = _s("tickets_panel_message").strip()[:1500]
    welcome = _s("tickets_open_message").strip()[:1500]
    try:
        tmax = max(1, min(int(form.get("tickets_max") or 1), 10))
    except Exception:
        tmax = 1
    config["tickets"] = {
        "enabled": form.get("tickets_enabled") == "on",
        "channel_id": _s("tickets_channel").strip(),
        "category_id": _s("tickets_category").strip(),
        "support_role_id": _s("tickets_support_role").strip(),
        "panel_title": (form.get("tickets_panel_title") or "🎫 Soporte").strip()[:100],
        "panel_description": panel_desc,
        "panel_message": panel_desc,
        "welcome_message": welcome,
        "open_message": welcome,
        "max_open_per_user": tmax,
        "options": options,
        "button_label": "Abrir ticket",
    }
    config["_panel_saved"] = True
    config["_saved_at"] = time.time()
    save_guild_config(guild_id, config)
    return RedirectResponse(f"/guild/{guild_id}/tickets?ok=1", status_code=303)




def _render_verify_result(request: Request, ok: bool, message: str):
    """HTML de resultado de verify. No depende de plantilla rota."""
    # Intentar plantilla correcta
    try:
        p = BASE_DIR / "templates" / "verify_result.html"
        if p.is_file():
            return templates.TemplateResponse(
                "verify_result.html",
                {"request": request, "ok": ok, "message": message},
            )
    except Exception as e:
        print(f"[verify] template: {e}")
    color = "#86efac" if ok else "#fca5a5"
    title = "Verificado" if ok else "No verificado"
    icon = "OK" if ok else "X"
    # escapar mensaje para HTML
    safe = (
        str(message or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    html = (
        "<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Verificacion · Odette</title><style>"
        "body{font-family:system-ui,sans-serif;background:#0b0e14;color:#e2e8f0;"
        "margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}"
        ".box{max-width:480px;padding:28px 24px;border-radius:16px;border:1px solid #1e293b;"
        "background:#111827;text-align:center}"
        "h1{margin:0 0 12px;font-size:1.45rem;color:" + color + "}"
        "p{color:#94a3b8;line-height:1.55;margin:0 0 22px}"
        "a{display:inline-block;padding:12px 22px;border-radius:999px;"
        "background:linear-gradient(135deg,#818cf8,#c084fc);color:#0b1220;"
        "font-weight:700;text-decoration:none}"
        "</style></head><body><div class='box'>"
        "<h1>" + icon + " " + title + "</h1>"
        "<p>" + safe + "</p>"
        "<a href='/dashboard'>Ir al panel</a>"
        "</div></body></html>"
    )
    return HTMLResponse(html)


# ── Verificación web ──

@app.get("/verify/{guild_id}", response_class=HTMLResponse)
async def verify_start(request: Request, guild_id: str, token: str = ""):
    """Verificación web: edad de cuenta + VPN opcional. Sin plantilla obligatoria."""
    try:
        if not str(guild_id).isdigit():
            return HTMLResponse("Servidor invalido", status_code=400)
        user = current_user(request)
        if not user:
            request.session["verify_next"] = f"/verify/{guild_id}?token={token}"
            return RedirectResponse("/login", status_code=303)

        cfg = get_guild_config(guild_id)
        vcfg = cfg.get("verify") or {}
        min_days = int(vcfg.get("min_account_days") or VERIFY_MIN_ACCOUNT_DAYS)
        block_vpn = bool(vcfg.get("block_vpn", True)) if "block_vpn" in vcfg else BLOCK_VPN

        tokens = _load_verify_tokens()
        key = f"{guild_id}:{token}"
        entry = tokens.get(key)
        if not token or not entry:
            return _render_verify_result(
                request, False, "Enlace invalido. Pide uno nuevo en Discord."
            )
        # multi_use: se puede reutilizar; used solo aplica a enlaces de un solo uso
        if entry.get("used") and not entry.get("multi_use"):
            return _render_verify_result(
                request, False, "Enlace ya usado. Pide uno nuevo en Discord."
            )
        if float(entry.get("exp", 0)) < time.time():
            return _render_verify_result(request, False, "Enlace caducado. Pide uno nuevo.")
        for_user = entry.get("for_user")
        if for_user and str(for_user) != str(user["id"]):
            return _render_verify_result(
                request, False, "Este enlace es para otra cuenta de Discord."
            )

        created = _discord_snowflake_created(user["id"])
        if created and min_days > 0:
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < min_days:
                return _render_verify_result(
                    request,
                    False,
                    f"Cuenta demasiado nueva ({age_days} dias). Minimo: {min_days} dias.",
                )

        ip = _client_ip(request)
        if block_vpn and IP_REPUTATION_KEY:
            risky, reason = await _ip_is_risky(ip)
            if risky:
                return _render_verify_result(
                    request,
                    False,
                    "No se permiten VPN/proxy para verificar. Desactivala e intentalo de nuevo.",
                )

        if not entry.get("multi_use"):
            entry["used"] = True
        entry["user_id"] = user["id"]
        entry["ip_hash"] = hashlib.sha256(ip.encode()).hexdigest()[:16]
        entry["verified_at"] = time.time()
        entry["uses"] = int(entry.get("uses") or 0) + 1
        tokens[key] = entry
        _save_verify_tokens(tokens)

        vdata = _load_verified_users()
        g = vdata.setdefault(str(guild_id), {})
        g[str(user["id"])] = {
            "at": time.time(),
            "ip_hash": entry["ip_hash"],
            "username": user.get("username"),
        }
        _save_verified_users(vdata)

        return _render_verify_result(
            request,
            True,
            "Verificacion completada. Vuelve a Discord; el bot te asignara el rol en unos segundos.",
        )
    except Exception as e:
        import traceback
        print(f"[verify] ERROR {guild_id}: {e}\n{traceback.format_exc()}")
        err = (
            str(e).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )[:200]
        html = (
            "<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>"
            "<title>Verificacion</title>"
            "<style>body{font-family:system-ui;background:#0b0e14;color:#e2e8f0;"
            "display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}"
            ".box{max-width:520px;padding:24px;border-radius:14px;border:1px solid #334155;"
            "background:#111827}code{color:#fca5a5}</style></head><body><div class='box'>"
            "<h1>Error en verificacion</h1>"
            "<p>El panel fallo al procesar el enlace. Pide uno nuevo en Discord.</p>"
            "<p><code>" + type(e).__name__ + ": " + err + "</code></p>"
            "<p><a href='/dashboard' style='color:#a5b4fc'>Ir al panel</a></p>"
            "</div></body></html>"
        )
        return HTMLResponse(html, status_code=500)


@app.get("/owner", response_class=HTMLResponse)
async def owner_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=303)
    if not is_owner(request):
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "user": current_user(request),
                "is_owner": False,
                "error": "Solo la dueña del bot.",
            },
            status_code=403,
        )
    data = _load_premium()
    return templates.TemplateResponse(
        "owner.html",
        {
            "request": request,
            "user": current_user(request),
            "is_owner": True,
            "premium_guilds": data.get("guilds") or {},
            "premium_users": data.get("users") or {},
            "csrf_token": _csrf_token(request),
        },
    )


def _add_premium_entry(bucket: str, target_id: str, duration: str) -> bool:
    ok, secs, label, err = parse_duration(duration)
    if not ok or not target_id.isdigit():
        return False
    data = _load_premium()
    store = data.setdefault(bucket, {})
    now = time.time()
    key = target_id.strip()
    if secs is None:
        store[key] = {"until": None, "label": "permanente", "added": now}
    else:
        prev = store.get(key) or {}
        base = now
        if prev.get("until"):
            try:
                pu = float(prev["until"])
                if pu > now:
                    base = pu
            except Exception:
                pass
        store[key] = {"until": base + secs, "label": label, "added": now}
    data[bucket] = store
    _save_premium(data)
    return True


@app.post("/owner/premium/add")
async def owner_premium_add(
    request: Request,
    target_id: str = Form(...),
    duration: str = Form("30d"),
    kind: str = Form("guild"),
    csrf_token: str = Form(""),
):
    if not is_owner(request):
        return RedirectResponse("/", status_code=303)
    if not _check_csrf(request, csrf_token):
        return RedirectResponse("/owner?err=csrf", status_code=303)
    bucket = "users" if (kind or "").strip().lower() == "user" else "guilds"
    _add_premium_entry(bucket, str(target_id).strip(), duration)
    return RedirectResponse("/owner", status_code=303)


@app.post("/owner/premium/remove")
async def owner_premium_remove(
    request: Request,
    target_id: str = Form(...),
    kind: str = Form("guild"),
    csrf_token: str = Form(""),
):
    if not is_owner(request):
        return RedirectResponse("/", status_code=303)
    if not _check_csrf(request, csrf_token):
        return RedirectResponse("/owner?err=csrf", status_code=303)
    bucket = "users" if (kind or "").strip().lower() == "user" else "guilds"
    data = _load_premium()
    (data.get(bucket) or {}).pop(str(target_id).strip(), None)
    _save_premium(data)
    return RedirectResponse("/owner", status_code=303)


# ───────────────────────── API bot ─────────────────────────

@app.get("/health")
async def health():
    return {
        "ok": True,
        "service": "odette-panel",
        "panel_token_len": len(PANEL_API_TOKEN or ""),
        "verify_vpn_api": bool(IP_REPUTATION_KEY),
    }


@app.get("/api/config-version")
async def api_config_version(request: Request):
    """El bot consulta esto cada ~2s. Devuelve version + guilds modificados."""
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    p = DATA_DIR / "config_version.txt"
    try:
        ver = float(p.read_text(encoding="utf-8").strip()) if p.is_file() else 0.0
    except Exception:
        ver = 0.0
    guild_ids = []
    try:
        dirty_path = DATA_DIR / "config_dirty.json"
        if dirty_path.is_file():
            import json as _json
            dirty = _json.loads(dirty_path.read_text(encoding="utf-8")) or {}
            guild_ids = list(dirty.get("guild_ids") or [])
            # Si el bot pide ?ack=1, limpiamos dirty tras leer
            if request.query_params.get("ack") == "1":
                dirty_path.write_text(_json.dumps({"guild_ids": [], "ts": time.time()}), encoding="utf-8")
    except Exception as e:
        print(f"[config-version] dirty: {e}")
    return JSONResponse({"ok": True, "version": ver, "guild_ids": guild_ids})


@app.get("/api/ping")
async def api_ping(request: Request):
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"ok": False, "error": "token invalido"}, status_code=401)
    return {"ok": True, "token_ok": True}



@app.get("/api/global/free_profile")
async def api_get_free_profile(request: Request):
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    return {"free_profile": is_free_profile()}


@app.post("/api/global/free_profile")
async def api_set_free_profile(request: Request):
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        body = {}
    on = bool((body or {}).get("free_profile"))
    set_free_profile(on)
    return {"ok": True, "free_profile": on}


@app.get("/api/guild/{guild_id}/config")
async def api_guild_config(guild_id: str, request: Request):
    if not str(guild_id).isdigit():
        return JSONResponse({"error": "guild_id invalido"}, status_code=400)
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    config = get_guild_config(guild_id)
    ok, status = is_premium(guild_id)
    free = is_free_profile()
    # asegurar bot_profile en respuesta
    if not isinstance(config.get("bot_profile"), dict):
        config["bot_profile"] = {
            "nick": None,
            "avatar_url": None,
            "footer": "Odette • El Lago de los Cisnes",
            "accent_emoji": "🦢",
            "custom_bio": None,
            "embed_color": config.get("embed_color") or "#AFD7E6",
            "status_note": None,
        }
    config["free_profile"] = free
    return {
        "guild_id": str(guild_id),
        "premium": ok,
        "premium_status": status,
        "free_profile": free,
        "has_saved": bool(config.get("_panel_saved")),
        "config": config,
    }


@app.post("/api/guild/{guild_id}/config")
async def api_guild_config_restore(guild_id: str, request: Request):
    """El bot empuja su config aquí.
    - force=true → siempre sobrescribe (cuando cambias algo desde Discord)
    - sin force → solo si el panel no tiene una versión más nueva
    """
    if not str(guild_id).isdigit():
        return JSONResponse({"error": "guild_id invalido"}, status_code=400)
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON invalido"}, status_code=400)
    force = bool(body.get("force")) if isinstance(body, dict) else False
    source = (body.get("source") or "bot") if isinstance(body, dict) else "bot"
    cfg = body.get("config") if isinstance(body, dict) and "config" in body else body
    if not isinstance(cfg, dict):
        return JSONResponse({"error": "config invalida"}, status_code=400)
    current = get_guild_config(guild_id)
    if (
        not force
        and current.get("_panel_saved")
        and float(current.get("_saved_at") or 0) > float(cfg.get("_saved_at") or 0)
    ):
        return {"ok": True, "restored": False, "reason": "panel_has_newer"}
    # Merge superficial: conservar claves del panel que el bot no manda
    merged = dict(current)
    for k, v in cfg.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            sub = dict(merged[k])
            sub.update(v)
            merged[k] = sub
        else:
            merged[k] = v
    merged["_panel_saved"] = True
    merged["_saved_at"] = time.time()
    merged["_source"] = str(source)[:32]
    save_guild_config(guild_id, merged)
    return {
        "ok": True,
        "restored": True,
        "guild_id": str(guild_id),
        "forced": force,
        "source": merged["_source"],
    }


@app.post("/api/guild/{guild_id}/verify/token")
async def api_create_verify_token(guild_id: str, request: Request):
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    if not str(guild_id).isdigit():
        return JSONResponse({"error": "guild_id invalido"}, status_code=400)
    try:
        body = await request.json()
    except Exception:
        body = {}
    user_id = str((body or {}).get("user_id") or "").strip()
    vt = secrets.token_urlsafe(24)
    tokens = _load_verify_tokens()
    multi_use = bool((body or {}).get("multi_use"))
    # multi_use: el mismo enlace sirve varias veces (miembros que salen y vuelven)
    # exp más larga si multi_use
    tokens[f"{guild_id}:{vt}"] = {
        "exp": time.time() + (86400 * 30 if multi_use else 900),
        "used": False,
        "multi_use": multi_use,
        "for_user": user_id or None,
    }
    _save_verify_tokens(tokens)
    base = _public_base()
    return {
        "token": vt,
        "url": f"{base}/verify/{guild_id}?token={vt}",
        "expires_in": 900,
    }


@app.get("/api/guild/{guild_id}/verify/status/{user_id}")
async def api_verify_status(guild_id: str, user_id: str, request: Request):
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    if not str(guild_id).isdigit() or not str(user_id).isdigit():
        return JSONResponse({"error": "id invalido"}, status_code=400)
    entry = (_load_verified_users().get(str(guild_id)) or {}).get(str(user_id))
    return {"verified": bool(entry), "data": entry}


@app.get("/api/user/{user_id}/premium")
async def api_user_premium(user_id: str, request: Request):
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    if not str(user_id).isdigit():
        return JSONResponse({"error": "user_id invalido"}, status_code=400)
    ok, status = is_user_premium(user_id)
    entry = (_load_premium().get("users") or {}).get(str(user_id)) or {}
    return {
        "user_id": str(user_id),
        "premium": ok,
        "premium_status": status,
        "until": entry.get("until"),
        "label": entry.get("label") or status,
    }




@app.get("/api/premium/export")
async def api_premium_export(request: Request):
    """Exporta guilds+users premium para que el bot sincronice 1:1."""
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    data = _load_premium()
    return JSONResponse({
        "guilds": data.get("guilds") or {},
        "users": data.get("users") or {},
        "free_profile": bool(data.get("free_profile")),
        "exported_at": __import__("time").time(),
    })


@app.post("/api/premium/import")
async def api_premium_import(request: Request):
    """El bot empuja su lista de premium (merge). force=true reemplaza buckets enviados."""
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    if not _safe_token_eq(token, PANEL_API_TOKEN):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON invalido"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "body invalido"}, status_code=400)
    force = bool(body.get("force"))
    data = _load_premium()
    if "guilds" in body and isinstance(body["guilds"], dict):
        if force:
            data["guilds"] = {str(k): v for k, v in body["guilds"].items()}
        else:
            data.setdefault("guilds", {})
            for k, v in body["guilds"].items():
                data["guilds"][str(k)] = v
    if "users" in body and isinstance(body["users"], dict):
        if force:
            data["users"] = {str(k): v for k, v in body["users"].items()}
        else:
            data.setdefault("users", {})
            for k, v in body["users"].items():
                data["users"][str(k)] = v
    if "free_profile" in body:
        data["free_profile"] = bool(body.get("free_profile"))
    _save_premium(data)
    return JSONResponse({
        "ok": True,
        "guilds": len(data.get("guilds") or {}),
        "users": len(data.get("users") or {}),
        "free_profile": bool(data.get("free_profile")),
    })


# ==================== BLACKLIST GLOBAL (panel ↔ bot) ====================
BLACKLIST_FILE = Path(os.getenv("DATA_DIR") or "data") / "global_blacklist.json"

def _bl_load() -> dict:
    try:
        BLACKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        if BLACKLIST_FILE.exists():
            import json as _json
            raw = _json.loads(BLACKLIST_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("users"), dict):
                return raw
    except Exception as e:
        print(f"[blacklist] load: {e}")
    return {"users": {}}

def _bl_save(data: dict):
    try:
        BLACKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        import json as _json
        BLACKLIST_FILE.write_text(_json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"[blacklist] save: {e}")

@app.get("/api/blacklist")
async def api_blacklist_list(request: Request):
    if not is_owner(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return JSONResponse(_bl_load())

@app.post("/api/blacklist")
async def api_blacklist_add(request: Request):
    if not is_owner(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "json"}, status_code=400)
    uid = str(body.get("user_id") or "").strip()
    if not uid.isdigit() or not (16 <= len(uid) <= 22):
        return JSONResponse({"ok": False, "error": "id inválido"}, status_code=400)
    reason = str(body.get("reason") or "panel")[:200]
    data = _bl_load()
    data.setdefault("users", {})[uid] = {
        "reason": reason,
        "source": "panel",
        "added_by": str((current_user(request) or {}).get("id") or ""),
        "at": __import__("time").time(),
    }
    _bl_save(data)
    return JSONResponse({"ok": True})

@app.delete("/api/blacklist/{user_id}")
async def api_blacklist_del(request: Request, user_id: str):
    if not is_owner(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    data = _bl_load()
    data.get("users", {}).pop(str(user_id), None)
    _bl_save(data)
    return JSONResponse({"ok": True})

@app.get("/api/blacklist/export")
async def api_blacklist_export(request: Request):
    """El bot puede leer con Bearer PANEL_API_TOKEN."""
    auth = (request.headers.get("Authorization") or "").replace("Bearer", "").strip()
    token = (os.getenv("PANEL_API_TOKEN") or "").strip()
    if not token or auth != token:
        # también owner sesión
        if not is_owner(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(_bl_load())

