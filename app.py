import os
import json
import secrets
import hashlib
import functools
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_from_directory, Response
from flask_cors import CORS
import pytz

app = Flask(__name__)
CORS(app)

# ==========================================
# KONFIGURASI
# ==========================================
TIMEZONE   = pytz.UTC
DOWNLOAD_FOLDER = 'downloads'
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

# Admin credentials — ganti sebelum deploy!
ADMIN_USER = os.environ.get('ADMIN_USER')
ADMIN_PASS = os.environ.get('ADMIN_PASS')

# Path JSON
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = '/tmp/licenses.json' if os.environ.get('VERCEL') else os.path.join(BASE_DIR, 'licenses.json')

# ==========================================
# ALCOHOL BRANDS
# ==========================================
ALCOHOL_BRANDS = [
    'JackDaniels','JohnnieWalker','Jameson','JimBeam','ChivasRegal',
    'Ballantines','Glenfiddich','Macallan','WildTurkey','MakersMark',
    'WoodfordReserve','BuffaloTrace','Bulleit','KnobCreek','EvanWilliams',
    'TheGlenlivet','Dewars','TullamoreDEW','CanadianClub','CrownRoyal',
    'SuntoryWhisky','Yamazaki','Hibiki','Nikka','Kavalan','Bushmills',
    'Teachers','JandB','MonkeyShoulder','Laphroaig','Lagavulin',
    'Talisker','Ardbeg','Bowmore','HighlandPark','Dalmore',
    'Glenmorangie','FourRoses','ElijahCraig','Seagrams7',
    'Smirnoff','Absolut','GreyGoose','Belvedere','Ciroc',
    'KetelOne','Stolichnaya','Skyy','TitosVodka','Finlandia',
    'RussianStandard','Svedka','Beluga','Pinnacle','Zubrowka',
    'Chopin','CrystalHead','Hangar1','Reyka','NewAmsterdam',
    'Patron','JoseCuervo','DonJulio','Herradura','Espolon',
    'OlmecaAltos','Sauza','Tequila1800','Casamigos','ClaseAzul',
    'Hornitos','ElJimador','Cazadores','Teremana','Avion',
    'Milagro','Corralejo','DelMaguey',
    'Bacardi','CaptainMorgan','HavanaClub','Malibu','Kraken',
    'AppletonEstate','MountGay','Diplomatico','RonZacapa','Plantation',
    'Myerss','SailorJerry','Brugal','Goslings','FlorDeCana','DonQ','Pyrat','Cruzan',
    'BombaySapphire','Tanqueray','Gordons','Beefeater','Hendricks',
    'SeagramsGin','Plymouth','RokuGin','TheBotanist','Monkey47',
    'Bulldog','Gilbeys','Aviation','Nolets','Sipsmith',
    'Hennessy','RemyMartin','Martell','Courvoisier','Camus',
    'Hine','Meukow','StRemy','Torres','Metaxa',
    'Jagermeister','Baileys','Kahlua','Cointreau','GrandMarnier',
    'Disaronno','Campari','Aperol','Frangelico','Chambord',
    'Midori','SouthernComfort','Drambuie','Galliano','TiaMaria',
    'Amarula','FernetBranca','Ricard','Pernod','Chartreuse','StGermain','Hpnotiq',
    'MoetChandon','DomPerignon','VeuveClicquot','Krug','Cristal','AceOfSpades',
    'Jinro','ChumChurum','Moutai','Wuliangye','Kubota','Dassai'
]

# ==========================================
# JSON DB HELPERS
# ==========================================

def load_db() -> dict:
    if not os.path.exists(DB_PATH):
        return {"licenses": {}, "banned_hwids": {}}
    try:
        with open(DB_PATH, 'r') as f:
            data = json.load(f)
            # Backward compat: tambah key baru jika DB lama
            if "banned_hwids" not in data:
                data["banned_hwids"] = {}
            return data
    except (json.JSONDecodeError, IOError):
        return {"licenses": {}, "banned_hwids": {}}

def save_db(data: dict):
    dir_ = os.path.dirname(DB_PATH)
    if dir_:
        os.makedirs(dir_, exist_ok=True)
    with open(DB_PATH, 'w') as f:
        json.dump(data, f, indent=2)

# ==========================================
# HELPERS
# ==========================================

def hash_hwid(hwid: str) -> str:
    return hashlib.sha256(hwid.encode('utf-8')).hexdigest()

def generate_license_key() -> str:
    db = load_db()
    existing = set(db["licenses"].keys())
    while True:
        brand      = secrets.choice(ALCOHOL_BRANDS)
        random_hex = secrets.token_hex(6)
        key = f"DTC_{brand}_{random_hex}"
        if len(key) > 40:
            key = key[:40]
        if key not in existing:
            return key

def calculate_expires_at(duration_type: str, start_time: datetime):
    if duration_type == 'lifetime':
        return None
    elif duration_type == 'demo_1min':
        return (start_time + timedelta(minutes=1)).isoformat()
    elif duration_type == 'trial_6hours':
        return (start_time + timedelta(hours=6)).isoformat()
    elif duration_type == '2weeks':
        return (start_time + timedelta(days=14)).isoformat()
    elif duration_type == '1month':
        return (start_time + timedelta(days=30)).isoformat()
    else:
        raise ValueError(f"Invalid duration_type: {duration_type}")

def parse_dt(iso_str: str) -> datetime:
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TIMEZONE)
    return dt

def now_iso() -> str:
    return datetime.now(TIMEZONE).isoformat()

def log_event(db: dict, license_key: str, event: str, detail: str = ""):
    """Tambah log aktivitas ke lisensi."""
    if license_key not in db["licenses"]:
        return
    if "logs" not in db["licenses"][license_key]:
        db["licenses"][license_key]["logs"] = []
    db["licenses"][license_key]["logs"].append({
        "time": now_iso(),
        "event": event,
        "detail": detail
    })
    # Simpan max 50 log per lisensi
    db["licenses"][license_key]["logs"] = db["licenses"][license_key]["logs"][-50:]

# ==========================================
# ADMIN AUTH (HTTP Basic)
# ==========================================

def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response(
                'Akses ditolak. Login required.',
                401,
                {'WWW-Authenticate': 'Basic realm="Admin Area"'}
            )
        return f(*args, **kwargs)
    return decorated

# ==========================================
# ROUTES — WEBSITE
# ==========================================

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception:
        return "PB Macro License Server is Running!", 200

@app.route('/download')
def download_file():
    return send_from_directory(app.config['DOWNLOAD_FOLDER'], "PBMacro.exe")

# ==========================================
# ROUTES — ADMIN DASHBOARD
# ==========================================

@app.route('/admin')
@requires_auth
def admin_dashboard():
    return render_template('admin.html')

@app.route('/admin/api/stats', methods=['GET'])
@requires_auth
def admin_stats():
    """Statistik ringkas untuk dashboard."""
    db = load_db()
    licenses = db["licenses"]
    now = datetime.now(TIMEZONE)

    total      = len(licenses)
    active     = sum(1 for l in licenses.values() if l["is_active"] and not l.get("is_banned"))
    expired    = sum(1 for l in licenses.values() if not l["is_active"] and not l.get("is_banned"))
    banned     = sum(1 for l in licenses.values() if l.get("is_banned"))
    unbound    = sum(1 for l in licenses.values() if l["hwid"] is None and l["is_active"])
    lifetime   = sum(1 for l in licenses.values() if l["duration_type"] == "lifetime")
    banned_hwids = len(db.get("banned_hwids", {}))

    # Aktivasi hari ini
    today_str  = now.strftime('%Y-%m-%d')
    activated_today = sum(
        1 for l in licenses.values()
        if l.get("last_used") and l["last_used"].startswith(today_str)
    )

    return jsonify({
        "total": total,
        "active": active,
        "expired": expired,
        "banned": banned,
        "unbound": unbound,
        "lifetime": lifetime,
        "banned_hwids": banned_hwids,
        "activated_today": activated_today
    })

@app.route('/admin/api/licenses', methods=['GET'])
@requires_auth
def admin_list_licenses():
    """List semua lisensi dengan filter & search."""
    db       = load_db()
    search   = request.args.get('search', '').lower()
    status   = request.args.get('status', 'all')   # all | active | expired | banned | unbound
    duration = request.args.get('duration', 'all')
    page     = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))

    now = datetime.now(TIMEZONE)
    result = []

    for key, lic in db["licenses"].items():
        # Filter search
        if search and search not in key.lower():
            continue

        # Hitung status
        is_banned   = lic.get("is_banned", False)
        is_active   = lic["is_active"] and not is_banned
        is_unbound  = lic["hwid"] is None and lic["is_active"] and not is_banned
        is_expired  = not lic["is_active"] and not is_banned

        # Hitung sisa waktu
        time_left = None
        if lic["expires_at"] and is_active:
            exp = parse_dt(lic["expires_at"])
            delta = exp - now
            if delta.total_seconds() > 0:
                hours = int(delta.total_seconds() // 3600)
                mins  = int((delta.total_seconds() % 3600) // 60)
                time_left = f"{hours}h {mins}m" if hours < 48 else f"{delta.days}d"
            else:
                time_left = "Expired"

        # Filter status
        if status == 'active'  and not is_active:   continue
        if status == 'expired' and not is_expired:  continue
        if status == 'banned'  and not is_banned:   continue
        if status == 'unbound' and not is_unbound:  continue
        if duration != 'all'   and lic["duration_type"] != duration: continue

        result.append({
            "license_key":   lic["license_key"],
            "hwid_short":    (lic["hwid"][:12] + "...") if lic["hwid"] else None,
            "hwid_full":     lic["hwid"],
            "duration_type": lic["duration_type"],
            "created_at":    lic["created_at"],
            "expires_at":    lic["expires_at"],
            "last_used":     lic.get("last_used"),
            "is_active":     is_active,
            "is_banned":     is_banned,
            "is_unbound":    is_unbound,
            "time_left":     time_left,
            "ban_reason":    lic.get("ban_reason", ""),
            "note":          lic.get("note", ""),
            "log_count":     len(lic.get("logs", [])),
        })

    # Sort: banned terakhir, aktif terbaru di atas
    result.sort(key=lambda x: (x["is_banned"], not x["is_active"], x["created_at"]), reverse=False)
    result.sort(key=lambda x: x["created_at"], reverse=True)

    total_filtered = len(result)
    start = (page - 1) * per_page
    end   = start + per_page

    return jsonify({
        "licenses": result[start:end],
        "total":    total_filtered,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, (total_filtered + per_page - 1) // per_page)
    })

@app.route('/admin/api/licenses/<license_key>/logs', methods=['GET'])
@requires_auth
def admin_get_logs(license_key):
    db = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"logs": db["licenses"][matched].get("logs", [])})

@app.route('/admin/api/licenses/<license_key>/note', methods=['POST'])
@requires_auth
def admin_set_note(license_key):
    """Tambah catatan ke lisensi (misal: nama buyer)."""
    data = request.get_json()
    db   = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"success": False, "message": "Not found"}), 404
    db["licenses"][matched]["note"] = data.get("note", "")
    log_event(db, matched, "NOTE_UPDATED", data.get("note", ""))
    save_db(db)
    return jsonify({"success": True})

@app.route('/admin/api/licenses/<license_key>/reset-hwid', methods=['POST'])
@requires_auth
def admin_reset_hwid(license_key):
    db = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"success": False, "message": "Not found"}), 404
    old_hwid = db["licenses"][matched].get("hwid", "none")
    db["licenses"][matched]["hwid"] = None
    log_event(db, matched, "HWID_RESET", f"Old: {old_hwid[:12] if old_hwid and old_hwid != 'none' else 'none'}")
    save_db(db)
    return jsonify({"success": True, "message": "HWID reset berhasil"})

@app.route('/admin/api/licenses/<license_key>/ban', methods=['POST'])
@requires_auth
def admin_ban_license(license_key):
    """Ban lisensi + opsional ban HWID-nya sekaligus."""
    data      = request.get_json() or {}
    reason    = data.get("reason", "Tidak ada alasan")
    ban_hwid  = data.get("ban_hwid", False)

    db = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"success": False, "message": "Not found"}), 404

    lic = db["licenses"][matched]
    lic["is_banned"]   = True
    lic["is_active"]   = False
    lic["ban_reason"]  = reason
    lic["banned_at"]   = now_iso()
    log_event(db, matched, "BANNED", reason)

    # Ban HWID juga jika diminta
    if ban_hwid and lic.get("hwid"):
        hwid_hash = lic["hwid"]
        db["banned_hwids"][hwid_hash] = {
            "hwid_hash":  hwid_hash,
            "reason":     reason,
            "banned_at":  now_iso(),
            "license_key": matched
        }
        log_event(db, matched, "HWID_BANNED", hwid_hash[:12])

    save_db(db)
    return jsonify({"success": True, "message": "Lisensi berhasil di-ban"})

@app.route('/admin/api/licenses/<license_key>/unban', methods=['POST'])
@requires_auth
def admin_unban_license(license_key):
    db = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"success": False, "message": "Not found"}), 404

    db["licenses"][matched]["is_banned"]  = False
    db["licenses"][matched]["is_active"]  = True
    db["licenses"][matched]["ban_reason"] = ""
    log_event(db, matched, "UNBANNED")
    save_db(db)
    return jsonify({"success": True, "message": "Lisensi berhasil di-unban"})

@app.route('/admin/api/licenses/<license_key>/deactivate', methods=['POST'])
@requires_auth
def admin_deactivate(license_key):
    db = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"success": False, "message": "Not found"}), 404
    db["licenses"][matched]["is_active"] = False
    log_event(db, matched, "DEACTIVATED", "Manual by admin")
    save_db(db)
    return jsonify({"success": True})

@app.route('/admin/api/licenses/<license_key>/reactivate', methods=['POST'])
@requires_auth
def admin_reactivate(license_key):
    db = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"success": False, "message": "Not found"}), 404
    if db["licenses"][matched].get("is_banned"):
        return jsonify({"success": False, "message": "Lisensi di-ban, unban dulu"}), 400
    db["licenses"][matched]["is_active"] = True
    log_event(db, matched, "REACTIVATED", "Manual by admin")
    save_db(db)
    return jsonify({"success": True})

@app.route('/admin/api/licenses/<license_key>/extend', methods=['POST'])
@requires_auth
def admin_extend(license_key):
    """Extend durasi lisensi (dalam hari)."""
    data = request.get_json() or {}
    days = int(data.get("days", 7))

    db = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"success": False, "message": "Not found"}), 404

    lic = db["licenses"][matched]
    if lic["duration_type"] == "lifetime":
        return jsonify({"success": False, "message": "Lisensi lifetime tidak perlu di-extend"}), 400

    now = datetime.now(TIMEZONE)
    if lic["expires_at"]:
        current_exp = parse_dt(lic["expires_at"])
        base = max(current_exp, now)
    else:
        base = now

    new_exp = (base + timedelta(days=days)).isoformat()
    lic["expires_at"] = new_exp
    lic["is_active"]  = True
    log_event(db, matched, "EXTENDED", f"+{days} hari → {new_exp[:10]}")
    save_db(db)
    return jsonify({"success": True, "new_expires": new_exp})

@app.route('/admin/api/licenses/<license_key>/delete', methods=['DELETE'])
@requires_auth
def admin_delete(license_key):
    db = load_db()
    matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
    if not matched:
        return jsonify({"success": False, "message": "Not found"}), 404
    del db["licenses"][matched]
    save_db(db)
    return jsonify({"success": True})

@app.route('/admin/api/banned-hwids', methods=['GET'])
@requires_auth
def admin_banned_hwids():
    db = load_db()
    return jsonify({"banned_hwids": list(db.get("banned_hwids", {}).values())})

@app.route('/admin/api/banned-hwids/<hwid_hash>/unban', methods=['POST'])
@requires_auth
def admin_unban_hwid(hwid_hash):
    db = load_db()
    if hwid_hash not in db.get("banned_hwids", {}):
        return jsonify({"success": False, "message": "HWID tidak ditemukan"}), 404
    del db["banned_hwids"][hwid_hash]
    save_db(db)
    return jsonify({"success": True})

# ==========================================
# ROUTES — API LICENSE (dari klien .exe)
# ==========================================

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    try:
        data = request.get_json()
        if not data or 'duration_type' not in data:
            return jsonify({"success": False, "message": "Missing duration_type"}), 400

        duration_type = data['duration_type']
        valid_types   = ['lifetime', '2weeks', '1month', 'demo_1min', 'trial_6hours']
        if duration_type not in valid_types:
            return jsonify({"success": False, "message": f"Invalid. Valid: {valid_types}"}), 400

        license_key = generate_license_key()
        created_at  = now_iso()
        note        = data.get("note", "")  # Opsional: nama buyer langsung saat generate

        db = load_db()
        db["licenses"][license_key] = {
            "license_key":   license_key,
            "hwid":          None,
            "duration_type": duration_type,
            "created_at":    created_at,
            "expires_at":    None,
            "is_active":     True,
            "is_banned":     False,
            "ban_reason":    "",
            "last_used":     None,
            "note":          note,
            "logs":          []
        }
        log_event(db, license_key, "GENERATED", f"Type: {duration_type}")
        save_db(db)

        return jsonify({
            "success":      True,
            "license_key":  license_key,
            "duration_type": duration_type,
            "message":      "License generated. Duration starts upon first activation."
        }), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/validate', methods=['POST'])
def validate_license():
    try:
        data = request.get_json()
        if not data or 'license_key' not in data or 'hwid' not in data:
            return jsonify({"success": False, "message": "Missing Data"}), 400

        license_key  = data['license_key'].strip()
        hwid         = data['hwid'].strip()
        hwid_hash    = hash_hwid(hwid)
        current_time = datetime.now(TIMEZONE)

        db = load_db()

        # Cek HWID banned
        if hwid_hash in db.get("banned_hwids", {}):
            return jsonify({"success": False, "message": "BANNED: Hardware ID anda telah diblokir"}), 403

        # Case-insensitive search
        matched = next((k for k in db["licenses"] if k.lower() == license_key.lower()), None)
        if not matched:
            return jsonify({"success": False, "message": "Invalid Key"}), 404

        lic = db["licenses"][matched]

        # Cek ban
        if lic.get("is_banned"):
            reason = lic.get("ban_reason", "Tidak ada alasan")
            return jsonify({"success": False, "message": f"BANNED: {reason}"}), 403

        if not lic["is_active"]:
            return jsonify({"success": False, "message": "EXPIRED: License Inactive"}), 403

        stored_hwid    = lic["hwid"]
        expires_at_str = lic["expires_at"]

        # Aktivasi pertama
        if stored_hwid is None:
            new_expires = calculate_expires_at(lic["duration_type"], current_time)
            lic["hwid"]       = hwid_hash
            lic["expires_at"] = new_expires
            lic["last_used"]  = current_time.isoformat()
            expires_at_str    = new_expires
            log_event(db, matched, "FIRST_ACTIVATION", f"HWID: {hwid_hash[:12]}")

        elif stored_hwid != hwid_hash:
            log_event(db, matched, "HWID_MISMATCH", f"Got: {hwid_hash[:12]}")
            save_db(db)
            return jsonify({"success": False, "message": "HWID Mismatch"}), 403

        # Cek expiry
        if expires_at_str:
            expires_at = parse_dt(expires_at_str)
            if current_time > expires_at:
                lic["is_active"] = False
                log_event(db, matched, "AUTO_EXPIRED")
                db["licenses"][matched] = lic
                save_db(db)
                return jsonify({"success": False, "message": "EXPIRED: Duration Ended"}), 403

        # Update last_used
        lic["last_used"] = current_time.isoformat()
        log_event(db, matched, "VALIDATED", f"HWID: {hwid_hash[:12]}")
        db["licenses"][matched] = lic
        save_db(db)

        return jsonify({
            "success":    True,
            "message":    "Valid",
            "duration":   lic["duration_type"],
            "expires_at": expires_at_str if expires_at_str else "Never"
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Server Error: {str(e)}"}), 500


# ==========================================
# ENTRY POINT
# ==========================================
application = app  # Vercel WSGI

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)