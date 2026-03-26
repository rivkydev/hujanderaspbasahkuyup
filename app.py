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
TIMEZONE        = pytz.UTC
DOWNLOAD_FOLDER = 'downloads'
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

ADMIN_USER       = os.environ.get('ADMIN_USER')
ADMIN_PASS       = os.environ.get('ADMIN_PASS')
GENERATE_API_KEY = os.environ.get('GENERATE_API_KEY')

MONGO_URI = os.environ.get('MONGO_URI')

# Script types yang valid
VALID_SCRIPT_TYPES = {"rapid_click", "macro_full"}

# ==========================================
# [FIX] WARNET SESSION TIMEOUT
# Jika server tidak menerima /validate dari device warnet dalam
# WARNET_SESSION_TIMEOUT detik, sesi dianggap mati dan slot dibebaskan.
# Client aktif validate tiap 30 detik → 5 menit = batas aman jika crash/kill.
# ==========================================
WARNET_SESSION_TIMEOUT = int(os.environ.get('WARNET_SESSION_TIMEOUT', 300))  # default 5 menit

# ==========================================
# DATABASE LAYER — MongoDB atau JSON fallback
# ==========================================
_mongo_client = None
_mongo_db     = None

def _get_mongo():
    global _mongo_client, _mongo_db
    if not MONGO_URI:
        return None, None
    try:
        if _mongo_client is None:
            from pymongo import MongoClient
            _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            _mongo_db     = _mongo_client.get_default_database()
        return _mongo_db["licenses"], _mongo_db["banned_hwids"]
    except Exception as e:
        print(f"[MongoDB] Connection error: {e}")
        return None, None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'licenses.json')

def _load_json() -> dict:
    if not os.path.exists(DB_PATH):
        return {"licenses": {}, "banned_hwids": {}}
    try:
        with open(DB_PATH, 'r') as f:
            data = json.load(f)
            if "banned_hwids" not in data:
                data["banned_hwids"] = {}
            return data
    except Exception:
        return {"licenses": {}, "banned_hwids": {}}

def _save_json(data: dict):
    with open(DB_PATH, 'w') as f:
        json.dump(data, f, indent=2)

# ==========================================
# PUBLIC DB API
# ==========================================

def get_license(key: str):
    col, _ = _get_mongo()
    if col is not None:
        doc = col.find_one({"license_key": {"$regex": f"^{key}$", "$options": "i"}})
        if doc:
            doc.pop("_id", None)
        return doc
    db = _load_json()
    matched = next((k for k in db["licenses"] if k.lower() == key.lower()), None)
    return db["licenses"].get(matched) if matched else None

def get_all_licenses() -> list:
    col, _ = _get_mongo()
    if col is not None:
        return list(col.find({}, {"_id": 0}))
    return list(_load_json()["licenses"].values())

def save_license(lic: dict):
    col, _ = _get_mongo()
    if col is not None:
        col.replace_one({"license_key": lic["license_key"]}, lic, upsert=True)
        return
    db = _load_json()
    db["licenses"][lic["license_key"]] = lic
    _save_json(db)

def delete_license(key: str):
    col, _ = _get_mongo()
    if col is not None:
        col.delete_one({"license_key": {"$regex": f"^{key}$", "$options": "i"}})
        return
    db = _load_json()
    matched = next((k for k in db["licenses"] if k.lower() == key.lower()), None)
    if matched:
        del db["licenses"][matched]
        _save_json(db)

def get_banned_hwid(hwid_hash: str):
    _, col = _get_mongo()
    if col is not None:
        doc = col.find_one({"hwid_hash": hwid_hash}, {"_id": 0})
        return doc
    return _load_json()["banned_hwids"].get(hwid_hash)

def get_all_banned_hwids() -> list:
    _, col = _get_mongo()
    if col is not None:
        return list(col.find({}, {"_id": 0}))
    return list(_load_json()["banned_hwids"].values())

def save_banned_hwid(entry: dict):
    _, col = _get_mongo()
    if col is not None:
        col.replace_one({"hwid_hash": entry["hwid_hash"]}, entry, upsert=True)
        return
    db = _load_json()
    db["banned_hwids"][entry["hwid_hash"]] = entry
    _save_json(db)

def delete_banned_hwid(hwid_hash: str):
    _, col = _get_mongo()
    if col is not None:
        col.delete_one({"hwid_hash": hwid_hash})
        return
    db = _load_json()
    db["banned_hwids"].pop(hwid_hash, None)
    _save_json(db)

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
# HELPERS
# ==========================================

def hash_hwid(hwid: str) -> str:
    return hashlib.sha256(hwid.encode('utf-8')).hexdigest()

def generate_license_key() -> str:
    existing = {l["license_key"] for l in get_all_licenses()}
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

def log_event(lic: dict, event: str, detail: str = ""):
    if "logs" not in lic:
        lic["logs"] = []
    lic["logs"].append({"time": now_iso(), "event": event, "detail": detail})
    lic["logs"] = lic["logs"][-50:]

def get_allowed_scripts(lic: dict) -> list:
    """Return list of scripts this license may use."""
    tier = lic.get("license_tier", "standard")
    if tier == "vip":
        return ["rapid_click", "macro_full"]
    scripts = lic.get("allowed_scripts", ["rapid_click"])
    if not isinstance(scripts, list) or not scripts:
        return ["rapid_click"]
    valid = [s for s in scripts if s in VALID_SCRIPT_TYPES]
    return valid if valid else ["rapid_click"]


# ==========================================
# [NEW] WARNET SESSION TIMEOUT HELPERS
# ==========================================

def is_warnet_session_timed_out(lic: dict, current_time: datetime) -> bool:
    """
    Cek apakah sesi warnet sudah timeout berdasarkan warnet_last_seen.
    Mengembalikan True jika sesi dianggap mati (harus di-clear).
    """
    if not lic.get("warnet_active_hwid"):
        return False  # Tidak ada sesi aktif, tidak perlu cek

    last_seen_str = lic.get("warnet_last_seen")
    if not last_seen_str:
        # Sesi lama sebelum patch ini diterapkan — tidak ada warnet_last_seen.
        # Gunakan warnet_session_start sebagai fallback. Jika juga tidak ada,
        # anggap sesi sudah stale (aman untuk di-clear).
        start_str = lic.get("warnet_session_start")
        if not start_str:
            return True  # Tidak ada timestamp sama sekali → anggap timeout
        try:
            start_dt = parse_dt(start_str)
            elapsed = (current_time - start_dt).total_seconds()
            # Toleransi lebih besar untuk sesi lama: 2x timeout
            return elapsed > (WARNET_SESSION_TIMEOUT * 2)
        except Exception:
            return True

    try:
        last_seen_dt = parse_dt(last_seen_str)
        elapsed = (current_time - last_seen_dt).total_seconds()
        return elapsed > WARNET_SESSION_TIMEOUT
    except Exception:
        return True  # Parse error → anggap timeout demi keamanan


def clear_warnet_session(lic: dict, reason: str = "TIMEOUT"):
    """Helper untuk membersihkan sesi warnet dan mencatat log."""
    old_hwid = lic.get("warnet_active_hwid") or "none"
    lic["warnet_active_hwid"]  = None
    lic["warnet_session_start"] = None
    lic["warnet_last_seen"]    = None
    log_event(lic, "WARNET_SESSION_EXPIRED",
              f"Reason: {reason} | Was: {str(old_hwid)[:12]}")


# ==========================================
# AUTH
# ==========================================

def check_auth(username, password):
    if not ADMIN_USER or not ADMIN_PASS:
        return False
    return username == ADMIN_USER and password == ADMIN_PASS

def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response('Akses ditolak.', 401, {'WWW-Authenticate': 'Basic realm="Admin"'})
        return f(*args, **kwargs)
    return decorated

def requires_generate_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if auth and check_auth(auth.username, auth.password):
            return f(*args, **kwargs)
        if GENERATE_API_KEY:
            api_key = request.headers.get('X-API-Key', '')
            if secrets.compare_digest(api_key, GENERATE_API_KEY):
                return f(*args, **kwargs)
        return Response('Akses ditolak.', 401, {'WWW-Authenticate': 'Basic realm="Admin"'})
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
    script = request.args.get('script', 'v1').lower()
    filename_map = {
        'v1': 'PBMacroV1.exe',
        'v2': 'PBMacroV2.exe',
    }
    filename = filename_map.get(script, 'PBMacroV1.exe')
    return send_from_directory(app.config['DOWNLOAD_FOLDER'], filename)

# ==========================================
# ROUTES — ADMIN
# ==========================================

@app.route('/admin')
@requires_auth
def admin_dashboard():
    return render_template('admin.html')

@app.route('/admin/api/stats')
@requires_auth
def admin_stats():
    try:
        licenses = get_all_licenses()
        now      = datetime.now(TIMEZONE)
        today    = now.strftime('%Y-%m-%d')

        total    = len(licenses)
        active   = sum(1 for l in licenses if l.get("is_active") and not l.get("is_banned"))
        expired  = sum(1 for l in licenses if not l.get("is_active") and not l.get("is_banned"))
        banned   = sum(1 for l in licenses if l.get("is_banned"))
        unbound  = sum(1 for l in licenses if l.get("hwid") is None and l.get("is_active"))
        lifetime = sum(1 for l in licenses if l.get("duration_type") == "lifetime")
        warnet   = sum(1 for l in licenses if l.get("is_warnet") and l.get("is_active") and not l.get("is_banned"))
        banned_hwids    = len(get_all_banned_hwids())
        activated_today = sum(1 for l in licenses if (l.get("last_used") or "").startswith(today))
        vip_active      = sum(1 for l in licenses if
                              l.get("license_tier") == "vip" and
                              l.get("is_active") and not l.get("is_banned"))

        # [NEW] Hitung sesi warnet yang sedang timeout (stuck)
        warnet_stuck = 0
        for l in licenses:
            if l.get("is_warnet") and l.get("warnet_active_hwid") and l.get("is_active"):
                if is_warnet_session_timed_out(l, now):
                    warnet_stuck += 1

        return jsonify({
            "total": total, "active": active, "expired": expired, "banned": banned,
            "unbound": unbound, "lifetime": lifetime, "banned_hwids": banned_hwids,
            "activated_today": activated_today, "warnet": warnet, "vip": vip_active,
            "warnet_stuck": warnet_stuck  # [NEW] info untuk admin
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/api/licenses')
@requires_auth
def admin_list_licenses():
    try:
        search   = request.args.get('search', '').lower().strip()
        status   = request.args.get('status', 'all')
        duration = request.args.get('duration', 'all')
        tier_f   = request.args.get('tier', 'all')
        page     = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 25))))
        now      = datetime.now(TIMEZONE)
        result   = []

        for lic in get_all_licenses():
            try:
                license_key   = lic.get("license_key", "")
                duration_type = lic.get("duration_type", "unknown")
                is_banned     = bool(lic.get("is_banned", False))
                is_active     = bool(lic.get("is_active", False))
                hwid          = lic.get("hwid")
                expires_at    = lic.get("expires_at")
                last_used     = lic.get("last_used")
                is_warnet     = bool(lic.get("is_warnet", False))
                warnet_active_hwid = lic.get("warnet_active_hwid")
                license_tier  = lic.get("license_tier", "standard")
                allowed_sc    = get_allowed_scripts(lic)

                if search:
                    note = (lic.get("note") or "").lower()
                    if search not in license_key.lower() and search not in note:
                        continue

                is_unbound      = (hwid is None) and is_active and not is_banned
                is_expired_flag = not is_active and not is_banned

                # [NEW] Cek apakah sesi warnet sudah timeout
                warnet_session_timed_out = (
                    is_warnet and bool(warnet_active_hwid) and
                    is_warnet_session_timed_out(lic, now)
                )

                time_left = None
                if expires_at and is_active and not is_unbound:
                    try:
                        exp   = parse_dt(expires_at)
                        delta = exp - now
                        if delta.total_seconds() > 0:
                            hours = int(delta.total_seconds() // 3600)
                            mins  = int((delta.total_seconds() % 3600) // 60)
                            time_left = f"{hours}h {mins}m" if hours < 48 else f"{delta.days}d"
                        else:
                            time_left = "Expired"
                    except Exception:
                        time_left = None

                if status == 'active'  and not (is_active and not is_banned):  continue
                if status == 'expired' and not is_expired_flag:                continue
                if status == 'banned'  and not is_banned:                      continue
                if status == 'unbound' and not is_unbound:                     continue
                if status == 'warnet'  and not (is_warnet and is_active and not is_banned): continue
                if status == 'vip'     and not (license_tier == 'vip' and is_active and not is_banned): continue

                if duration != 'all' and duration_type != duration:
                    continue
                if tier_f != 'all' and license_tier != tier_f:
                    continue

                result.append({
                    "license_key":         license_key,
                    "hwid_short":          (hwid[:12] + "...") if hwid else None,
                    "hwid_full":           hwid,
                    "duration_type":       duration_type,
                    "created_at":          lic.get("created_at", ""),
                    "expires_at":          expires_at,
                    "last_used":           last_used,
                    "is_active":           is_active and not is_banned,
                    "is_banned":           is_banned,
                    "is_unbound":          is_unbound,
                    "is_warnet":           is_warnet,
                    "warnet_active_hwid":  warnet_active_hwid,
                    "warnet_session_start": lic.get("warnet_session_start"),
                    "warnet_last_seen":    lic.get("warnet_last_seen"),          # [NEW]
                    "warnet_session_timed_out": warnet_session_timed_out,        # [NEW]
                    "time_left":           time_left,
                    "ban_reason":          lic.get("ban_reason", ""),
                    "note":                lic.get("note", ""),
                    "log_count":           len(lic.get("logs", [])),
                    "license_tier":        license_tier,
                    "allowed_scripts":     allowed_sc,
                })
            except Exception as row_err:
                print(f"[admin_list] Skipping bad doc: {row_err}")
                continue

        result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        total_filtered = len(result)
        start = (page - 1) * per_page

        return jsonify({
            "licenses": result[start:start + per_page],
            "total":    total_filtered,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total_filtered + per_page - 1) // per_page)
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/admin/api/licenses/<license_key>/logs')
@requires_auth
def admin_get_logs(license_key):
    lic = get_license(license_key)
    if not lic:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"logs": lic.get("logs", [])})

@app.route('/admin/api/licenses/<license_key>/note', methods=['POST'])
@requires_auth
def admin_set_note(license_key):
    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404
    lic["note"] = (request.get_json() or {}).get("note", "")
    log_event(lic, "NOTE_UPDATED", lic["note"])
    save_license(lic)
    return jsonify({"success": True})

@app.route('/admin/api/licenses/<license_key>/reset-hwid', methods=['POST'])
@requires_auth
def admin_reset_hwid(license_key):
    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404
    old = (lic.get("hwid") or "none")
    lic["hwid"] = None
    if lic.get("is_warnet"):
        lic["warnet_active_hwid"]    = None
        lic["warnet_session_start"]  = None
        lic["warnet_last_seen"]      = None  # [NEW]
        log_event(lic, "HWID_RESET", f"Old: {old[:12]} | Warnet sesi dibersihkan")
    else:
        log_event(lic, "HWID_RESET", f"Old: {old[:12]} | Sisa waktu dipertahankan")
    save_license(lic)
    return jsonify({"success": True, "message": "HWID reset berhasil. Sisa waktu dipertahankan."})

@app.route('/admin/api/licenses/<license_key>/ban', methods=['POST'])
@requires_auth
def admin_ban_license(license_key):
    data     = request.get_json() or {}
    reason   = data.get("reason", "Tidak ada alasan")
    ban_hwid = data.get("ban_hwid", False)

    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404

    lic["is_banned"]  = True
    lic["is_active"]  = False
    lic["ban_reason"] = reason
    lic["banned_at"]  = now_iso()
    lic["warnet_active_hwid"]   = None
    lic["warnet_session_start"] = None
    lic["warnet_last_seen"]     = None  # [NEW]
    log_event(lic, "BANNED", reason)

    if ban_hwid and lic.get("hwid"):
        hwid_hash = lic["hwid"]
        save_banned_hwid({"hwid_hash": hwid_hash, "reason": reason,
                          "banned_at": now_iso(), "license_key": lic["license_key"]})
        log_event(lic, "HWID_BANNED", hwid_hash[:12])

    save_license(lic)
    return jsonify({"success": True, "message": "Lisensi berhasil di-ban"})

@app.route('/admin/api/licenses/<license_key>/unban', methods=['POST'])
@requires_auth
def admin_unban_license(license_key):
    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404
    lic["is_banned"]  = False
    lic["is_active"]  = True
    lic["ban_reason"] = ""
    log_event(lic, "UNBANNED")
    save_license(lic)
    return jsonify({"success": True, "message": "Lisensi berhasil di-unban"})

@app.route('/admin/api/licenses/<license_key>/deactivate', methods=['POST'])
@requires_auth
def admin_deactivate(license_key):
    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404
    lic["is_active"] = False
    lic["warnet_active_hwid"]   = None
    lic["warnet_session_start"] = None
    lic["warnet_last_seen"]     = None  # [NEW]
    log_event(lic, "DEACTIVATED", "Manual by admin")
    save_license(lic)
    return jsonify({"success": True, "message": "Lisensi dinonaktifkan"})

@app.route('/admin/api/licenses/<license_key>/reactivate', methods=['POST'])
@requires_auth
def admin_reactivate(license_key):
    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404
    if lic.get("is_banned"):
        return jsonify({"success": False, "message": "Lisensi di-ban, unban dulu"}), 400
    lic["is_active"] = True
    log_event(lic, "REACTIVATED", "Manual by admin")
    save_license(lic)
    return jsonify({"success": True, "message": "Lisensi diaktifkan kembali"})

@app.route('/admin/api/licenses/<license_key>/extend', methods=['POST'])
@requires_auth
def admin_extend(license_key):
    data = request.get_json() or {}
    days = int(data.get("days", 7))
    lic  = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404
    if lic.get("duration_type") == "lifetime":
        return jsonify({"success": False, "message": "Lisensi lifetime tidak perlu di-extend"}), 400

    now  = datetime.now(TIMEZONE)
    base = max(parse_dt(lic["expires_at"]), now) if lic.get("expires_at") else now
    new_exp = (base + timedelta(days=days)).isoformat()
    lic["expires_at"] = new_exp
    lic["is_active"]  = True
    log_event(lic, "EXTENDED", f"+{days} hari → {new_exp[:10]}")
    save_license(lic)
    return jsonify({"success": True, "new_expires": new_exp})

@app.route('/admin/api/licenses/<license_key>/delete', methods=['DELETE'])
@requires_auth
def admin_delete(license_key):
    if not get_license(license_key):
        return jsonify({"success": False, "message": "Not found"}), 404
    delete_license(license_key)
    return jsonify({"success": True, "message": "Lisensi dihapus"})

@app.route('/admin/api/licenses/<license_key>/set-tier', methods=['POST'])
@requires_auth
def admin_set_tier(license_key):
    data     = request.get_json() or {}
    new_tier = data.get("tier", "").lower()

    if new_tier not in ("standard", "vip"):
        return jsonify({"success": False, "message": "Tier tidak valid. Gunakan 'standard' atau 'vip'"}), 400

    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404

    if lic.get("duration_type") != "lifetime":
        return jsonify({"success": False, "message": "Tier hanya bisa diubah pada lisensi Lifetime"}), 400

    if lic.get("is_banned"):
        return jsonify({"success": False, "message": "Lisensi di-ban, tidak bisa diubah"}), 400

    old_tier = lic.get("license_tier", "standard")
    if old_tier == new_tier:
        return jsonify({"success": False, "message": f"Lisensi sudah tier {new_tier}"}), 400

    lic["license_tier"] = new_tier

    if new_tier == "vip":
        lic["allowed_scripts"] = ["rapid_click", "macro_full"]
        log_event(lic, "TIER_CHANGED", f"{old_tier} → vip | Scripts: V1+V2")
        msg = "Lisensi berhasil di-upgrade ke Lifetime VIP (V1 + V2)"
    else:
        lic["allowed_scripts"] = ["rapid_click"]
        log_event(lic, "TIER_CHANGED", f"vip → standard | Scripts: V1 only")
        msg = "Lisensi di-downgrade ke Standard V1"

    save_license(lic)
    return jsonify({
        "success":         True,
        "message":         msg,
        "license_tier":    new_tier,
        "allowed_scripts": lic["allowed_scripts"]
    })

@app.route('/admin/api/licenses/<license_key>/set-warnet', methods=['POST'])
@requires_auth
def admin_set_warnet(license_key):
    data      = request.get_json() or {}
    is_warnet = bool(data.get("is_warnet", True))

    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404

    lic["is_warnet"] = is_warnet
    if is_warnet:
        lic["hwid"]                 = None
        lic["warnet_active_hwid"]   = None
        lic["warnet_session_start"] = None
        lic["warnet_last_seen"]     = None  # [NEW]
        log_event(lic, "WARNET_ENABLED", "Mode warnet diaktifkan, HWID lock dihapus")
    else:
        lic["warnet_active_hwid"]   = None
        lic["warnet_session_start"] = None
        lic["warnet_last_seen"]     = None  # [NEW]
        log_event(lic, "WARNET_DISABLED", "Mode warnet dinonaktifkan")

    save_license(lic)
    return jsonify({"success": True, "is_warnet": is_warnet,
                    "message": f"Mode warnet {'diaktifkan' if is_warnet else 'dinonaktifkan'}"})

@app.route('/admin/api/licenses/<license_key>/warnet-logout', methods=['POST'])
@requires_auth
def admin_warnet_logout(license_key):
    lic = get_license(license_key)
    if not lic:
        return jsonify({"success": False, "message": "Not found"}), 404
    if not lic.get("is_warnet"):
        return jsonify({"success": False, "message": "Bukan lisensi warnet"}), 400

    old_hwid = lic.get("warnet_active_hwid") or "none"
    lic["warnet_active_hwid"]   = None
    lic["warnet_session_start"] = None
    lic["warnet_last_seen"]     = None  # [NEW]
    log_event(lic, "WARNET_FORCE_LOGOUT", f"Admin clear sesi. Was: {str(old_hwid)[:12]}")
    save_license(lic)
    return jsonify({"success": True, "message": "Sesi warnet berhasil di-clear"})

@app.route('/admin/api/banned-hwids')
@requires_auth
def admin_banned_hwids():
    return jsonify({"banned_hwids": get_all_banned_hwids()})

@app.route('/admin/api/banned-hwids/<hwid_hash>/unban', methods=['POST'])
@requires_auth
def admin_unban_hwid(hwid_hash):
    if not get_banned_hwid(hwid_hash):
        return jsonify({"success": False, "message": "HWID tidak ditemukan"}), 404
    delete_banned_hwid(hwid_hash)
    return jsonify({"success": True, "message": "HWID berhasil di-unban"})


# ==========================================
# [NEW] ADMIN: CLEANUP WARNET STUCK SESSIONS
# Trigger manual untuk bersihkan semua sesi warnet yang sudah timeout.
# Berguna jika banyak user yang crash sekaligus.
# ==========================================
@app.route('/admin/api/cleanup-warnet', methods=['POST'])
@requires_auth
def admin_cleanup_warnet():
    """
    Bersihkan semua sesi warnet yang sudah timeout (tidak ada validasi > WARNET_SESSION_TIMEOUT detik).
    """
    try:
        now      = datetime.now(TIMEZONE)
        cleaned  = 0
        licenses = get_all_licenses()

        for lic in licenses:
            if not lic.get("is_warnet"):
                continue
            if not lic.get("warnet_active_hwid"):
                continue
            if not lic.get("is_active") or lic.get("is_banned"):
                continue

            if is_warnet_session_timed_out(lic, now):
                clear_warnet_session(lic, reason=f"ADMIN_CLEANUP timeout>{WARNET_SESSION_TIMEOUT}s")
                save_license(lic)
                cleaned += 1

        return jsonify({
            "success": True,
            "cleaned": cleaned,
            "message": f"{cleaned} sesi warnet dibersihkan",
            "timeout_seconds": WARNET_SESSION_TIMEOUT
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ==========================================
# ROUTES — API LICENSE (dari klien .exe)
# ==========================================

@app.route('/api/generate-key', methods=['POST'])
@requires_generate_auth
def generate_key():
    try:
        data = request.get_json()
        if not data or 'duration_type' not in data:
            return jsonify({"success": False, "message": "Missing duration_type"}), 400

        duration_type = data['duration_type']
        valid_types   = ['lifetime', '2weeks', '1month', 'demo_1min', 'trial_6hours']
        if duration_type not in valid_types:
            return jsonify({"success": False, "message": f"Invalid. Valid: {valid_types}"}), 400

        is_warnet    = bool(data.get("is_warnet", False))
        license_tier = data.get("license_tier", "standard")
        if license_tier not in ("standard", "vip"):
            license_tier = "standard"

        allowed_scripts = data.get("allowed_scripts", ["rapid_click"])
        if not isinstance(allowed_scripts, list):
            allowed_scripts = ["rapid_click"]
        allowed_scripts = [s for s in allowed_scripts if s in VALID_SCRIPT_TYPES]
        if not allowed_scripts:
            allowed_scripts = ["rapid_click"]

        if license_tier == "vip":
            if duration_type != "lifetime":
                license_tier    = "standard"
            else:
                allowed_scripts = ["rapid_click", "macro_full"]

        license_key = generate_license_key()
        lic = {
            "license_key":          license_key,
            "hwid":                 None,
            "duration_type":        duration_type,
            "created_at":           now_iso(),
            "expires_at":           None,
            "is_active":            True,
            "is_banned":            False,
            "ban_reason":           "",
            "last_used":            None,
            "note":                 data.get("note", ""),
            "is_warnet":            is_warnet,
            "license_tier":         license_tier,
            "allowed_scripts":      allowed_scripts,
            "warnet_active_hwid":   None,
            "warnet_session_start": None,
            "warnet_last_seen":     None,  # [NEW]
            "logs":                 []
        }
        log_event(lic, "GENERATED",
                  f"Type: {duration_type} | Tier: {license_tier} | Scripts: {','.join(allowed_scripts)} | Warnet: {is_warnet}")
        save_license(lic)

        return jsonify({
            "success":         True,
            "license_key":     license_key,
            "duration_type":   duration_type,
            "is_warnet":       is_warnet,
            "license_tier":    license_tier,
            "allowed_scripts": allowed_scripts,
            "message":         "License generated. Duration starts upon first activation."
        }), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/validate', methods=['POST'])
def validate_license():
    try:
        data = request.get_json()
        if not data or 'license_key' not in data or 'hwid' not in data:
            return jsonify({"success": False, "message": "Missing Data"}), 400

        license_key = data['license_key'].strip()
        hwid        = data['hwid'].strip()
        script_type = data.get('script_type', 'rapid_click').strip()

        if not license_key or not hwid:
            return jsonify({"success": False, "message": "license_key dan hwid tidak boleh kosong"}), 400

        hwid_hash    = hash_hwid(hwid)
        current_time = datetime.now(TIMEZONE)

        if get_banned_hwid(hwid_hash):
            return jsonify({"success": False, "message": "BANNED: Hardware ID anda telah diblokir"}), 403

        lic = get_license(license_key)
        if not lic:
            return jsonify({"success": False, "message": "Invalid Key"}), 404

        if lic.get("is_banned"):
            return jsonify({"success": False,
                            "message": f"BANNED: {lic.get('ban_reason', 'Tidak ada alasan')}"}), 403

        if not lic.get("is_active"):
            return jsonify({"success": False, "message": "EXPIRED: License Inactive"}), 403

        allowed = get_allowed_scripts(lic)
        if script_type in VALID_SCRIPT_TYPES and script_type not in allowed:
            log_event(lic, "TIER_DENIED", f"Requested: {script_type} | Allowed: {','.join(allowed)}")
            save_license(lic)
            return jsonify({
                "success":         False,
                "message":         "TIER_DENIED: Lisensi tidak memiliki akses ke script ini",
                "required_tier":   "vip",
                "allowed_scripts": allowed
            }), 403

        is_warnet      = bool(lic.get("is_warnet", False))
        stored_hwid    = lic.get("hwid")
        expires_at_str = lic.get("expires_at")

        # ── MODE WARNET ──────────────────────────────────────────────────
        if is_warnet:
            warnet_active = lic.get("warnet_active_hwid")

            # [FIX] Cek apakah sesi yang sedang aktif sudah timeout
            # Jika ya, clear dulu sebelum cek HWID — sehingga device baru bisa masuk
            if warnet_active and warnet_active != hwid_hash:
                if is_warnet_session_timed_out(lic, current_time):
                    # Sesi lama sudah mati (crash/kill), otomatis bebaskan slot
                    clear_warnet_session(
                        lic,
                        reason=f"AUTO_TIMEOUT >{WARNET_SESSION_TIMEOUT}s | New: {hwid_hash[:12]}"
                    )
                    warnet_active = None  # Sesi sudah di-clear, lanjut ke blok di bawah
                    log_event(lic, "WARNET_AUTO_FREED",
                              f"Session expired, slot freed for new device: {hwid_hash[:12]}")
                else:
                    # Sesi masih aktif dan valid → tolak device lain
                    log_event(lic, "WARNET_LOCKED", f"Active: {str(warnet_active)[:12]} | Blocked: {hwid_hash[:12]}")
                    save_license(lic)
                    return jsonify({
                        "success": False,
                        "message": "WARNET_LOCKED: Lisensi sedang digunakan di device lain"
                    }), 403

            if not warnet_active:
                # Mulai sesi baru
                lic["warnet_active_hwid"]   = hwid_hash
                lic["warnet_session_start"] = current_time.isoformat()
                lic["warnet_last_seen"]     = current_time.isoformat()  # [NEW]

                if not expires_at_str and lic.get("duration_type") != "lifetime":
                    expires_at_str    = calculate_expires_at(lic["duration_type"], current_time)
                    lic["expires_at"] = expires_at_str
                    log_event(lic, "WARNET_FIRST_ACTIVATION",
                              f"HWID: {hwid_hash[:12]} | Expires: {(expires_at_str or 'Never')[:19]}")
                else:
                    log_event(lic, "WARNET_SESSION_START", f"HWID: {hwid_hash[:12]}")
            else:
                # Sesi milik HWID yang sama → update last_seen (heartbeat)
                lic["warnet_last_seen"] = current_time.isoformat()  # [NEW] ← kunci utama fix ini
                log_event(lic, "WARNET_REVALIDATED", f"HWID: {hwid_hash[:12]}")

        # ── MODE NORMAL ──────────────────────────────────────────────────
        else:
            if stored_hwid is None:
                lic["hwid"] = hwid_hash

                if not expires_at_str and lic.get("duration_type") != "lifetime":
                    expires_at_str    = calculate_expires_at(lic["duration_type"], current_time)
                    lic["expires_at"] = expires_at_str
                    log_event(lic, "FIRST_ACTIVATION", f"HWID: {hwid_hash[:12]}")
                else:
                    log_event(lic, "HWID_REBOUND",
                              f"HWID: {hwid_hash[:12]} | Timer lanjut, Expires: {(expires_at_str or 'Never')[:19]}")

            elif stored_hwid != hwid_hash:
                log_event(lic, "HWID_MISMATCH", f"Got: {hwid_hash[:12]}")
                save_license(lic)
                return jsonify({"success": False, "message": "HWID Mismatch"}), 403

        # ── Cek expired ──────────────────────────────────────────────────
        expires_at_str = lic.get("expires_at")
        if expires_at_str and expires_at_str not in ("Never", "null", None):
            if current_time > parse_dt(expires_at_str):
                lic["is_active"] = False
                if is_warnet:
                    lic["warnet_active_hwid"]   = None
                    lic["warnet_session_start"] = None
                    lic["warnet_last_seen"]     = None  # [NEW]
                log_event(lic, "AUTO_EXPIRED")
                save_license(lic)
                return jsonify({"success": False, "message": "EXPIRED: Duration Ended"}), 403

        lic["last_used"] = current_time.isoformat()
        log_event(lic, "VALIDATED", f"HWID: {hwid_hash[:12]} | Script: {script_type}")
        save_license(lic)

        return jsonify({
            "success":         True,
            "message":         "Valid",
            "duration":        lic["duration_type"],
            "expires_at":      expires_at_str if expires_at_str else "Never",
            "mode":            "warnet" if is_warnet else "normal",
            "license_tier":    lic.get("license_tier", "standard"),
            "allowed_scripts": allowed,
            "session_timeout": WARNET_SESSION_TIMEOUT,  # [NEW] info ke client (opsional)
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Server Error: {str(e)}"}), 500


@app.route('/api/logout', methods=['POST'])
def logout_license():
    try:
        data = request.get_json()
        if not data or 'license_key' not in data or 'hwid' not in data:
            return jsonify({"success": False, "message": "Missing Data"}), 400

        license_key = data['license_key'].strip()
        hwid        = data['hwid'].strip()
        hwid_hash   = hash_hwid(hwid)

        lic = get_license(license_key)
        if not lic:
            return jsonify({"success": False, "message": "Invalid Key"}), 404

        if not lic.get("is_warnet"):
            return jsonify({"success": True, "message": "OK"}), 200

        if lic.get("warnet_active_hwid") == hwid_hash:
            lic["warnet_active_hwid"]   = None
            lic["warnet_session_start"] = None
            lic["warnet_last_seen"]     = None  # [NEW]
            log_event(lic, "WARNET_LOGOUT", f"HWID: {hwid_hash[:12]}")
            save_license(lic)

        return jsonify({"success": True, "message": "Logged out"}), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Server Error: {str(e)}"}), 500
# ============================================================
#  TAMBAHKAN KE app.py
#  Letakkan setelah route /api/validate
#  Edit MACRO_VERSIONS setiap kali ada binary V3 baru
# ============================================================

# ── Versi & URL download macro V3 ─────────────────────────
# Setiap kali push binary V3 baru:
#   1. Upload .exe ke GitHub Releases / CDN / direct URL
#   2. Update "version" dan "url" di sini
#   3. Deploy → semua loader yang aktif otomatis update saat aktivasi berikutnya
MACRO_V3_VERSION = "3.0.1"
MACRO_V3_URL     = "https://GANTI_DENGAN_URL_DOWNLOAD_V3_EXE"
# Contoh GitHub Releases:
# MACRO_V3_URL = "https://github.com/USERMU/REPO/releases/download/v3.0.1/PBMacroV3.exe"


@app.route('/api/macro-info', methods=['POST'])
def macro_info():
    """
    Dipanggil loader setelah validasi berhasil.
    Return: versi terbaru + URL download.
    Loader pakai ini untuk cek update — download hanya jika versi beda.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Missing data"}), 400

        license_key = (data.get('license_key') or '').strip()
        hwid        = (data.get('hwid') or '').strip()
        script_type = (data.get('script_type') or '').strip()

        if not license_key or not hwid:
            return jsonify({"success": False, "message": "Missing fields"}), 400

        # Validasi ringan — pastikan lisensi masih valid & punya akses V3
        lic = get_license(license_key)
        if not lic:
            return jsonify({"success": False, "message": "License not found"}), 404
        if lic.get("is_banned"):
            return jsonify({"success": False, "message": "BANNED"}), 403
        if not lic.get("is_active"):
            return jsonify({"success": False, "message": "EXPIRED"}), 403

        # Cek tier — V3 hanya untuk macro_full / VIP
        # Untuk sekarang: macro_v3 memakai tier "macro_full"
        # Jika nanti ada tier tersendiri, sesuaikan di sini
        allowed = get_allowed_scripts(lic)
        if "macro_full" not in allowed and lic.get("license_tier") != "vip":
            return jsonify({
                "success": False,
                "message": "TIER_DENIED: Upgrade ke VIP untuk akses V3"
            }), 403

        return jsonify({
            "success":     True,
            "version":     MACRO_V3_VERSION,
            "url":         MACRO_V3_URL,
            "script_type": "macro_v3",
            "changelog":   ""   # opsional, bisa isi nanti
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# ==========================================
# ENTRY POINT
# ==========================================
application = app  # Vercel WSGI

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)