import os
import sys
import time
import json
import math
import sqlite3
import logging
import uuid
import subprocess
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="GiG VPN Server")

INBOUND_ID = 1
XUI_DB_PATH = "/etc/x-ui/x-ui.db"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

FREE_IP_LIMITS = {}
PAID_IP_LIMITS = {}


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            days_left INTEGER DEFAULT 30,
            expires_at INTEGER DEFAULT 0
        )
    """)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN expires_at INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


init_db()


def get_client_ip(request: Request) -> str:
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_user(username: str, password: str):
    if not username or not password:
        return None
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT username, days_left, expires_at FROM users WHERE username = ? AND password = ?",
        (username.strip(), password.strip())
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    uname, old_days, expires_at = row[0], row[1], row[2]
    now = int(time.time())

    if not expires_at or expires_at == 0:
        expires_at = now + (old_days * 86400)
        cur.execute("UPDATE users SET expires_at = ? WHERE username = ?", (expires_at, uname))
        conn.commit()

    conn.close()

    seconds_left = max(0, expires_at - now)
    days_left = math.ceil(seconds_left / 86400) if seconds_left > 0 else 0
    return {"username": uname, "days_left": days_left}


@app.get("/", response_class=HTMLResponse)
async def serve_home():
    template_path = os.path.join(BASE_DIR, "templates", "index.html")
    if not os.path.exists(template_path):
        return HTMLResponse(content="<h1>Файл index.html не найден</h1>", status_code=404)
    with open(template_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.post("/api/login")
async def api_login(username: str = Form(...), password: str = Form(...)):
    user = get_user(username, password)
    if not user:
        return JSONResponse(status_code=401, content={"success": False, "error": "Неверный логин или пароль"})
    status_text = "Premium Активен" if user["days_left"] > 0 else "Подписка истекла"
    return {
        "success": True,
        "username": user["username"],
        "days_left": user["days_left"],
        "status": status_text
    }


@app.post("/api/generate-key")
async def api_generate_key(
    request: Request,
    country: str = Form("se"),
    username: str = Form(""),
    password: str = Form("")
):
    if country != "se":
        return JSONResponse(status_code=400, content={"success": False, "error": "Эта локация скоро появится. Выберите Швецию."})

    client_ip = get_client_ip(request)
    now = time.time()

    user = get_user(username, password)
    is_paid = user is not None and user["days_left"] > 0

    if is_paid:
        last_req = PAID_IP_LIMITS.get(client_ip, 0)
        if now - last_req < 10:
            return JSONResponse(status_code=429, content={"success": False, "error": "Подождите 10 секунд перед созданием следующего ключа."})
        PAID_IP_LIMITS[client_ip] = now
    else:
        last_req = FREE_IP_LIMITS.get(client_ip, 0)
        if now - last_req < 86400:
            hours_left = math.ceil((86400 - (now - last_req)) / 3600)
            return JSONResponse(
                status_code=429,
                content={"success": False, "error": f"Бесплатный ключ можно получать 1 раз в сутки. Попробуйте снова через {hours_left} ч."}
            )
        FREE_IP_LIMITS[client_ip] = now

    total_gb_bytes = 0 if is_paid else (3 * 1024 * 1024 * 1024)

    try:
        client_id = str(uuid.uuid4())
        prefix = f"pro_{user['username']}" if is_paid else "free"
        email = f"{prefix}_{client_id[:6]}"

        new_client = {
            "id": client_id,
            "flow": "xtls-rprx-vision",
            "email": email,
            "limitIp": 2 if is_paid else 1,
            "totalGB": total_gb_bytes,
            "expiryTime": 0,
            "enable": True,
            "tgId": 0,
            "subId": client_id
        }

        conn = sqlite3.connect(XUI_DB_PATH, timeout=15.0)
        cur = conn.cursor()
        cur.execute("SELECT settings FROM inbounds WHERE id = ?", (INBOUND_ID,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return JSONResponse(status_code=500, content={"success": False, "error": f"Подключение ID {INBOUND_ID} не найдено в базе"})

        settings = json.loads(row[0])
        if "clients" not in settings:
            settings["clients"] = []
        settings["clients"].append(new_client)

        cur.execute("UPDATE inbounds SET settings = ? WHERE id = ?", (json.dumps(settings), INBOUND_ID))
        conn.commit()
        conn.close()

        # Фоновый перезапуск без задержки ответа пользователю
        subprocess.Popen(["systemctl", "restart", "x-ui"])

        # ВАЖНО: Reality-параметры ниже ДОЛЖНЫ совпадать с настройками на вашем VPS!
        # pbk  = public key (из xray config Reality)
        # sid  = short ID (из xray config Reality)
        # sni  = SNI target (домен, который маскирует трафик)
        # spx  = path для XHTTP mode (должен совпадать с Xray)
        vless_key = (
            f"vless://{client_id}@45.83.24.18:8443"
            f"?encryption=none"
            f"&flow=xtls-rprx-vision"
            f"&fp=chrome"
            f"&pbk=wCyJFML_o2zRiVubWAu7Ilh2dJeC8SMTUqPYva_XMyg"
            f"&security=reality"
            f"&sid=8454a05293"
            f"&sni=images.apple.com"
            f"&spx=%2Fb42Rsr4trOdVSEh"
            f"&type=tcp"
            f"&padding=1"
            f"#GiG-Sweden-{email}"
        )

        return {"success": True, "key": vless_key}

    except Exception as e:
        logger.error(f"Сбой генерации: {str(e)}")
        return JSONResponse(status_code=500, content={"success": False, "error": f"Ошибка базы панели: {str(e)}"})


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "add":
        u_name = sys.argv[2]
        u_pass = sys.argv[3]
        u_days = int(sys.argv[4]) if len(sys.argv) > 4 else 30
        expires = int(time.time()) + (u_days * 86400)
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO users (username, password, days_left, expires_at) VALUES (?, ?, ?, ?)",
            (u_name, u_pass, u_days, expires)
        )
        conn.commit()
        conn.close()
        print(f"Пользователь {u_name} добавлен на {u_days} дн.")
    else:
        import uvicorn
        uvicorn.run("main:app", host="0.0.0.0", port=8000)
