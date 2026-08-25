"""
Odette Panel — completo
- OAuth Discord, dashboard, config por servidor
- Mensajes editables: welcome, booster, verify
- Cuarentena: crear rol, nombre, strip roles, logs
- Premium guild + user
- API bot: GET config + POST restore

Deploy Render:
  Build: pip install -r requirements.txt
  Start: uvicorn main:app --host 0.0.0.0 --port $PORT
"""
from __future__ import annotations

import json
import os
import secrets
import time
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
PREMIUM_FILE = DATA_DIR / "premium_guilds.json"
CONFIG_FILE = DATA_DIR / "guild_configs.json"

DISCORD_CLIENT_ID = (os.getenv("DISCORD_CLIENT_ID") or "").strip()
DISCORD_CLIENT_SECRET = (os.getenv("DISCORD_CLIENT_SECRET") or "").strip()
DISCORD_REDIRECT_URI = (os.getenv("DISCORD_REDIRECT_URI") or "").strip()
BOT_OWNER_ID = int(os.getenv("BOT_OWNER_ID") or "545930956721356842")
SECRET_KEY = (os.getenv("SECRET_KEY") or secrets.token_hex(32)).strip()

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
_RATE_WINDOW = 60.0
_RATE_MAX = 90
_RATE_API_MAX = 30


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
            "style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response


app.add_middleware(SecurityHeadersMiddleware)


def _safe_token_eq(a: str, b: str) -> bool:
    try:
        return _hmac.compare_digest((a or "").encode(), (b or "").encode())
    except Exception:
        return False


def _csrf_token(request: Request) -> str:
    tok = request.session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["_csrf"] = tok
    return tok


def _check_csrf(request: Request, form_token: str) -> bool:
    expected = request.session.get("_csrf") or ""
    return _safe_token_eq(expected, (form_token or "").strip())


_STATIC = BASE_DIR / "static"
_STATIC.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ───────────────────────── Premium ─────────────────────────

def _load_premium() -> dict:
    if not PREMIUM_FILE.exists():
        return {"guilds": {}, "users": {}}
    try:
        data = json.loads(PREMIUM_FILE.read_text(encoding="utf-8"))
        if isinstance(data.get("guilds"), list):
            data["guilds"] = {
                str(x): {"until": None, "label": "permanente"} for x in data["guilds"]
            }
        if not isinstance(data.get("guilds"), dict):
            data["guilds"] = {}
        if not isinstance(data.get("users"), dict):
            data["users"] = {}
        return data
    except Exception:
        return {"guilds": {}, "users": {}}


def _save_premium(data: dict) -> None:
    data.setdefault("guilds", {})
    data.setdefault("users", {})
    PREMIUM_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


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
        return False, None, None, "Formato: permanente | 7d | 24h | 30d | 1d12h"
    total = 0
    for num, unit in re.findall(r"(\d+)([dhms])", t):
        n = int(num)
        if unit == "d":
            total += n * 86400
        elif unit == "h":
            total += n * 3600
        elif unit == "m":
            total += n * 60
        else:
            total += n
    if total <= 0:
        return False, None, None, "Duración inválida"
    parts = []
    d, r = divmod(total, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m and not d:
        parts.append(f"{m}m")
    return True, total, "".join(parts), None


def _premium_entry_status(entry: dict | None) -> tuple[bool, str]:
    if not entry:
        return False, "no"
    until = entry.get("until")
    if until is None:
        return True, "permanente"
    try:
        left = float(until) - time.time()
    except Exception:
        return False, "no"
    if left <= 0:
        return False, "expirado"
    d, r = divmod(int(left), 86400)
    h, _ = divmod(r, 3600)
    return True, f"queda {d}d {h}h" if d else f"queda {h}h"


def is_premium(guild_id: str | int) -> tuple[bool, str]:
    data = _load_premium()
    gid = str(guild_id)
    entry = (data.get("guilds") or {}).get(gid)
    ok, status = _premium_entry_status(entry)
    if status == "expirado" and entry:
        (data.get("guilds") or {}).pop(gid, None)
        _save_premium(data)
    return ok, status


def is_user_premium(user_id: str | int) -> tuple[bool, str]:
    data = _load_premium()
    uid = str(user_id)
    entry = (data.get("users") or {}).get(uid)
    ok, status = _premium_entry_status(entry)
    if status == "expirado" and entry:
        (data.get("users") or {}).pop(uid, None)
        _save_premium(data)
    return ok, status


# ───────────────────────── Config ─────────────────────────

def _default_config() -> dict:
    return {
        "anti_raid": {"enabled": False, "max_joins": 5, "window": 10},
        "automod": {"enabled": False, "anti_invite": True},
        "verify": {
            "enabled": False,
            "channel_id": "",
            "role_id": "",
            "message": "Bienvenido. Verifícate para acceder al servidor.",
        },
        "logs": {"enabled": False, "channel_id": ""},
        "ia": {"enabled": False},
        "welcome": {
            "enabled": False,
            "channel_id": "",
            "message": "¡Bienvenido {user} a **{server}**!",
        },
        "autorole": {"enabled": False, "role_id": ""},
        "levels": {"enabled": False},
        "booster": {
            "enabled": False,
            "channel_id": "",
            "message": "¡Gracias {user} por potenciar **{server}**! 🚀",
        },
        "tickets": {"enabled": False},
        "starboard": {"enabled": False, "channel_id": "", "min_stars": 3},
        "nsfw": {"enabled": True},
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
        "invites": {"enabled": False},
        "sticky": {"enabled": False},
        "autoresponse": {"enabled": False},
        "afk": {"enabled": True},
        "snipe": {"enabled": True},
        "tempvc": {"enabled": False},
        "giveaways": {"enabled": True},
        "reminders": {"enabled": True},
        "economy": {"enabled": True},
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
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


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


def save_guild_config(guild_id: str, config: dict) -> None:
    all_cfg = _load_all_configs()
    all_cfg[str(guild_id)] = config
    _save_all_configs(all_cfg)


def current_user(request: Request) -> Optional[dict]:
    return request.session.get("user")


def is_owner(request: Request) -> bool:
    u = current_user(request)
    return bool(u and int(u.get("id", 0)) == BOT_OWNER_ID)


def _clean_secret(val: str) -> str:
    v = (val or "").strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        v = v[1:-1].strip()
    return v


PANEL_API_TOKEN = "yZLUyyjWWSuAYU_hB8u22U3-asSG85fIbP4mKJ_gVRQ"


# ───────────────────────── Rutas web ─────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": current_user(request), "is_owner": is_owner(request)},
    )


@app.get("/login")
async def login(request: Request):
    if not DISCORD_CLIENT_ID or not DISCORD_REDIRECT_URI:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "user": None,
                "is_owner": False,
                "error": "Faltan DISCORD_CLIENT_ID o DISCORD_REDIRECT_URI.",
            },
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
    return RedirectResponse(f"{OAUTH_AUTHORIZE}?{urlencode(params)}")


@app.get("/callback")
async def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return RedirectResponse("/?error=oauth")
    if not code or state != request.session.get("oauth_state"):
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "user": None,
                "is_owner": False,
                "error": "Login inválido (state/code).",
            },
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
                {
                    "request": request,
                    "user": None,
                    "is_owner": False,
                    "error": f"Token Discord falló ({token_res.status_code}).",
                },
                status_code=400,
            )
        token = token_res.json()
        access = token.get("access_token")
        me = await client.get(
            f"{API_BASE}/users/@me",
            headers={"Authorization": f"Bearer {access}"},
        )
        guilds = await client.get(
            f"{API_BASE}/users/@me/guilds",
            headers={"Authorization": f"Bearer {access}"},
        )
    if me.status_code != 200:
        return RedirectResponse("/")
    user = me.json()
    request.session["user"] = {
        "id": str(user["id"]),
        "username": user.get("global_name") or user.get("username"),
        "avatar": user.get("avatar"),
    }
    ADMIN = 0x8
    glist = []
    if guilds.status_code == 200:
        for g in guilds.json():
            try:
                perms = int(g.get("permissions", 0))
            except Exception:
                perms = 0
            if (perms & ADMIN) or (perms & 0x20):
                glist.append(
                    {
                        "id": str(g["id"]),
                        "name": g.get("name") or "Server",
                        "icon": g.get("icon"),
                    }
                )
    request.session["guilds"] = glist
    request.session.pop("oauth_state", None)
    return RedirectResponse("/dashboard")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "is_owner": is_owner(request),
            "guilds": request.session.get("guilds") or [],
        },
    )


@app.get("/guild/{guild_id}", response_class=HTMLResponse)
async def guild_page(request: Request, guild_id: str):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    guilds = request.session.get("guilds") or []
    guild = next((g for g in guilds if str(g["id"]) == str(guild_id)), None)
    if not guild and not is_owner(request):
        return RedirectResponse("/dashboard")
    if not guild:
        guild = {"id": guild_id, "name": f"Server {guild_id}", "icon": None}

    ok_g, status_g = is_premium(guild_id)
    ok_u, status_u = is_user_premium(user["id"])
    premium_ok = ok_g or ok_u
    premium_status = status_g if ok_g else (status_u if ok_u else "no")

    return templates.TemplateResponse(
        "guild.html",
        {
            "request": request,
            "user": user,
            "is_owner": is_owner(request),
            "guild": guild,
            "premium": premium_ok,
            "premium_status": premium_status,
            "config": get_guild_config(guild_id),
            "csrf_token": _csrf_token(request),
        },
    )


@app.post("/guild/{guild_id}/save")
async def guild_save(request: Request, guild_id: str):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")

    guilds = request.session.get("guilds") or []
    has_access = any(str(g["id"]) == str(guild_id) for g in guilds) or is_owner(request)
    if not has_access:
        return RedirectResponse("/dashboard")

    form = await request.form()
    if not _check_csrf(request, str(form.get("csrf_token") or "")):
        return RedirectResponse(f"/guild/{guild_id}?err=csrf", status_code=303)
    if not str(guild_id).isdigit():
        return RedirectResponse("/dashboard")

    def _int(name, default=0):
        try:
            return int(form.get(name) or default)
        except Exception:
            return default

    config = {
        "anti_raid": {
            "enabled": form.get("anti_raid_enabled") == "on",
            "max_joins": max(1, min(_int("anti_raid_max_joins", 5), 50)),
            "window": max(5, min(_int("anti_raid_window", 10), 120)),
        },
        "automod": {
            "enabled": form.get("automod_enabled") == "on",
            "anti_invite": form.get("automod_anti_invite") == "on",
        },
        "verify": {
            "enabled": form.get("verify_enabled") == "on",
            "channel_id": (form.get("verify_channel") or "").strip(),
            "role_id": (form.get("verify_role") or "").strip(),
            "message": (form.get("verify_message") or "").strip()[:1000],
        },
        "logs": {
            "enabled": form.get("logs_enabled") == "on",
            "channel_id": (form.get("logs_channel") or "").strip(),
        },
        "ia": {"enabled": form.get("ia_enabled") == "on"},
        "welcome": {
            "enabled": form.get("welcome_enabled") == "on",
            "channel_id": (form.get("welcome_channel") or "").strip(),
            "message": (form.get("welcome_message") or "").strip()[:1500],
        },
        "autorole": {
            "enabled": form.get("autorole_enabled") == "on",
            "role_id": (form.get("autorole_role") or "").strip(),
        },
        "levels": {"enabled": form.get("levels_enabled") == "on"},
        "booster": {
            "enabled": form.get("booster_enabled") == "on",
            "channel_id": (form.get("booster_channel") or "").strip(),
            "message": (form.get("booster_message") or "").strip()[:1500],
        },
        "tickets": {"enabled": form.get("tickets_enabled") == "on"},
        "starboard": {
            "enabled": form.get("starboard_enabled") == "on",
            "channel_id": (form.get("starboard_channel") or "").strip(),
            "min_stars": max(1, min(_int("starboard_min", 3), 25)),
        },
        "nsfw": {"enabled": form.get("nsfw_enabled") == "on"},
        "raidmode": {"enabled": form.get("raidmode_enabled") == "on"},
        "antihoist": {"enabled": form.get("antihoist_enabled") == "on"},
        "quarantine": {
            "enabled": form.get("quarantine_enabled") == "on",
            "role_id": (form.get("quarantine_role") or "").strip(),
            "create_role": form.get("quarantine_create_role") == "on",
            "role_name": (form.get("quarantine_role_name") or "Cuarentena").strip()[:80]
            or "Cuarentena",
            "strip_roles": form.get("quarantine_strip_roles") == "on",
            "log_channel_id": (form.get("quarantine_log_channel") or "").strip(),
        },
        "reports": {
            "enabled": form.get("reports_enabled") == "on",
            "channel_id": (form.get("reports_channel") or "").strip(),
        },
        "suggest": {
            "enabled": form.get("suggest_enabled") == "on",
            "channel_id": (form.get("suggest_channel") or "").strip(),
        },
        "modnotes": {"enabled": form.get("modnotes_enabled") == "on"},
        "watchlist": {"enabled": form.get("watchlist_enabled") == "on"},
        "reaction_roles": {"enabled": form.get("reaction_roles_enabled") == "on"},
        "invites": {"enabled": form.get("invites_enabled") == "on"},
        "sticky": {"enabled": form.get("sticky_enabled") == "on"},
        "autoresponse": {"enabled": form.get("autoresponse_enabled") == "on"},
        "afk": {"enabled": form.get("afk_enabled") == "on"},
        "snipe": {"enabled": form.get("snipe_enabled") == "on"},
        "tempvc": {"enabled": form.get("tempvc_enabled") == "on"},
        "giveaways": {"enabled": form.get("giveaways_enabled") == "on"},
        "reminders": {"enabled": form.get("reminders_enabled") == "on"},
        "economy": {"enabled": form.get("economy_enabled") == "on"},
        "profiles": {"enabled": form.get("profiles_enabled") == "on"},
        "marriage": {"enabled": form.get("marriage_enabled") == "on"},
        "actions_sfw": {"enabled": form.get("actions_sfw_enabled") == "on"},
        "music": {"enabled": form.get("music_enabled") == "on"},
        "fun": {"enabled": form.get("fun_enabled") == "on"},
    }

    ok_g, _ = is_premium(guild_id)
    ok_u, _ = is_user_premium(user["id"])
    if not (ok_g or ok_u):
        config["ia"]["enabled"] = False

    config["_panel_saved"] = True
    config["_saved_at"] = time.time()
    save_guild_config(guild_id, config)
    return RedirectResponse(f"/guild/{guild_id}?ok=1", status_code=303)


@app.get("/owner", response_class=HTMLResponse)
async def owner_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/login")
    if not is_owner(request):
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "user": current_user(request),
                "is_owner": False,
                "error": "Solo la dueña del bot puede entrar a Owner.",
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
    key = str(target_id).strip()
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
    store = data.get(bucket) or {}
    store.pop(str(target_id).strip(), None)
    data[bucket] = store
    _save_premium(data)
    return RedirectResponse("/owner", status_code=303)


# ───────────────────────── API bot ─────────────────────────

@app.get("/health")
async def health():
    tlen = len(_clean_secret(PANEL_API_TOKEN) or "")
    return {
        "ok": True,
        "service": "odette-panel",
        "phase": 2,
        "panel_token_configured": tlen > 0,
        "panel_token_len": tlen,
    }


@app.get("/api/ping")
async def api_ping(request: Request):
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    expected = _clean_secret(PANEL_API_TOKEN)
    if not _safe_token_eq(token, expected):
        return JSONResponse({"ok": False, "error": "token invalido"}, status_code=401)
    return {"ok": True, "service": "odette-panel", "token_ok": True}


@app.get("/api/guild/{guild_id}/config")
async def api_guild_config(guild_id: str, request: Request):
    if not str(guild_id).isdigit():
        return JSONResponse({"error": "guild_id invalido"}, status_code=400)
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    expected = _clean_secret(PANEL_API_TOKEN)
    if not expected or not _safe_token_eq(token, expected):
        return JSONResponse({"error": "No autorizado"}, status_code=401)

    config = get_guild_config(guild_id)
    ok, status = is_premium(guild_id)
    return {
        "guild_id": str(guild_id),
        "premium": ok,
        "premium_status": status,
        "has_saved": bool(config.get("_panel_saved")),
        "config": config,
    }


@app.post("/api/guild/{guild_id}/config")
async def api_guild_config_restore(guild_id: str, request: Request):
    """El bot restaura la config si el panel perdió el JSON."""
    if not str(guild_id).isdigit():
        return JSONResponse({"error": "guild_id invalido"}, status_code=400)
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    expected = _clean_secret(PANEL_API_TOKEN)
    if not expected or not _safe_token_eq(token, expected):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON invalido"}, status_code=400)

    cfg = body.get("config") if isinstance(body, dict) and "config" in body else body
    if not isinstance(cfg, dict):
        return JSONResponse({"error": "config invalida"}, status_code=400)

    current = get_guild_config(guild_id)
    cur_ts = float(current.get("_saved_at") or 0)
    new_ts = float(cfg.get("_saved_at") or 0)
    if current.get("_panel_saved") and cur_ts > new_ts:
        return {
            "ok": True,
            "restored": False,
            "reason": "panel_has_newer",
            "guild_id": str(guild_id),
        }

    cfg["_panel_saved"] = True
    if "_saved_at" not in cfg:
        cfg["_saved_at"] = time.time()
    save_guild_config(guild_id, cfg)
    return {"ok": True, "restored": True, "guild_id": str(guild_id)}


@app.get("/api/user/{user_id}/premium")
async def api_user_premium(user_id: str, request: Request):
    auth = request.headers.get("Authorization") or ""
    token = _clean_secret(auth.replace("Bearer ", "").replace("bearer ", ""))
    expected = _clean_secret(PANEL_API_TOKEN)
    if not expected or not _safe_token_eq(token, expected):
        return JSONResponse({"error": "No autorizado"}, status_code=401)
    if not str(user_id).isdigit():
        return JSONResponse({"error": "user_id invalido"}, status_code=400)
    ok, status = is_user_premium(user_id)
    return {"user_id": str(user_id), "premium": ok, "premium_status": status}
