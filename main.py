import os
import sys
import json
import sqlite3
import logging
import uuid
import httpx
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="GiG VPN Server")

PANEL_URL = "https://127.0.0:15999/hVlVlSDyhYHkDPBo0k"
INBOUND_ID = 1
PANEL_USERNAME = "GIG-ADMIN"
PANEL_PASSWORD = "12Azzz5672814_GIG"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            days_left INTEGER DEFAULT 30
        )
    """)
    conn.commit()
    conn.close()


init_db()


def get_user(username: str, password: str):
    if not username or not password:
        return None
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT username, days_left FROM users WHERE username = ? AND password = ?",
        (username.strip(), password.strip())
    )
    row = cur.fetchone()
    conn.close()
    if row:
        return {"username": row[0], "days_left": row[1]}
    return None


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
    country: str = Form("se"),
    username: str = Form(""),
    password: str = Form("")
):
    if country != "se":
        return JSONResponse(status_code=400, content={"success": False, "error": "Эта локация скоро появится. Выберите Швецию."})

    user = get_user(username, password)
    is_paid = user is not None and user["days_left"] > 0
    total_gb_bytes = 0 if is_paid else (3 * 1024 * 1024 * 1024)

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            headers = {
                "Origin": "https://127.0.0.1:15999",
                "Referer": f"{PANEL_URL}/"
            }

            login_resp = await client.post(
                f"{PANEL_URL}/login",
                data={"username": PANEL_USERNAME, "password": PANEL_PASSWORD},
                headers=headers
            )

            if login_resp.status_code != 200 or not login_resp.json().get("success"):
                logger.error(f"Ошибка входа в 3x-ui: {login_resp.status_code} {login_resp.text}")
                return JSONResponse(status_code=500, content={"success": False, "error": "Ошибка авторизации в панели"})

            client_id = str(uuid.uuid4())
            prefix = f"pro_{user['username']}" if is_paid else "free"
            email = f"{prefix}_{client_id[:6]}"

            client_settings = {
                "clients": [
                    {
                        "id": client_id,
                        "flow": "",
                        "email": email,
                        "limitIp": 2 if is_paid else 1,
                        "totalGB": total_gb_bytes,
                        "expiryTime": 0,
                        "enable": True,
                        "tgId": "",
                        "subId": ""
                    }
                ]
            }

            add_resp = await client.post(
                f"{PANEL_URL}/panel/api/inbounds/addClient",
                json={"id": INBOUND_ID, "settings": json.dumps(client_settings)},
                headers=headers
            )

            if add_resp.status_code != 200 or not add_resp.json().get("success"):
                logger.error(f"Ошибка создания клиента: {add_resp.status_code} {add_resp.text}")
                return JSONResponse(status_code=500, content={"success": False, "error": "Панель отклонила создание ключа"})

            vless_key = (
                f"vless://{client_id}@45.83.24.18:443"
                f"?encryption=mlkem768x25519plus.native.0rtt.GwRzUooVLudmEKQfsE4XsP3WPj4Gnjs9JFJOIHdv-Ao"
                f"&fp=chrome"
                f"&pbk=HqlpqhydKAptgfDtshOFVNqlI0GxuC7NKETfUPDXRSw"
                f"&security=reality"
                f"&sid=b85f52aa04df6ed9"
                f"&sni=microsoft.com"
                f"&spx=%2F8fbbcfe8969b423"
                f"&support-x25519mlkem768=true"
                f"&type=tcp"
                f"#Sweden-VLESS-{email}"
            )

            return {"success": True, "key": vless_key}

    except Exception as e:
        logger.error(f"Сбой генерации: {str(e)}")
        return JSONResponse(status_code=500, content={"success": False, "error": f"Ошибка сервера: {str(e)}"})


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "add":
        u_name = sys.argv[2]
        u_pass = sys.argv[3]
        u_days = int(sys.argv[4]) if len(sys.argv) > 4 else 30
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO users (username, password, days_left) VALUES (?, ?, ?)", (u_name, u_pass, u_days))
        conn.commit()
        conn.close()
        print(f"Пользователь {u_name} добавлен на {u_days} дн.")
    else:
        import uvicorn
        uvicorn.run("main:app", host="0.0.0.0", port=80)
