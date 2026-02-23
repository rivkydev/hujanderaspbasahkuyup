import os
import json
import secrets
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import pytz

app = Flask(__name__)
CORS(app)

# ==========================================
# KONFIGURASI
# ==========================================
TIMEZONE = pytz.UTC
DOWNLOAD_FOLDER = 'downloads'
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

# Path file JSON — di Vercel pakai /tmp (satu-satunya folder writable)
# PENTING: /tmp di Vercel bersifat ephemeral (reset setiap cold start).
# Untuk production, ganti dengan database eksternal seperti:
#   - PlanetScale (MySQL), Supabase (PostgreSQL), MongoDB Atlas, Upstash (Redis)
# Untuk sekarang /tmp sudah cukup jika traffic tidak terlalu tinggi.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/tmp/licenses.json' if os.environ.get('VERCEL') else os.path.join(BASE_DIR, 'licenses.json')

# ==========================================
# LIST BRAND (untuk generate key)
# ==========================================
ALCOHOL_BRANDS = [
    # WHISKEY / SCOTCH / BOURBON
    'JackDaniels', 'JohnnieWalker', 'Jameson', 'JimBeam', 'ChivasRegal',
    'Ballantines', 'Glenfiddich', 'Macallan', 'WildTurkey', 'MakersMark',
    'WoodfordReserve', 'BuffaloTrace', 'Bulleit', 'KnobCreek', 'EvanWilliams',
    'TheGlenlivet', 'Dewars', 'TullamoreDEW', 'CanadianClub', 'CrownRoyal',
    'SuntoryWhisky', 'Yamazaki', 'Hibiki', 'Nikka', 'Kavalan', 'Bushmills',
    'Teachers', 'JandB', 'MonkeyShoulder', 'Laphroaig', 'Lagavulin',
    'Talisker', 'Ardbeg', 'Bowmore', 'HighlandPark', 'Dalmore',
    'Glenmorangie', 'FourRoses', 'ElijahCraig', 'Seagrams7',
    # VODKA
    'Smirnoff', 'Absolut', 'GreyGoose', 'Belvedere', 'Ciroc',
    'KetelOne', 'Stolichnaya', 'Skyy', 'TitosVodka', 'Finlandia',
    'RussianStandard', 'Svedka', 'Beluga', 'Pinnacle', 'Zubrowka',
    'Chopin', 'CrystalHead', 'Hangar1', 'Reyka', 'NewAmsterdam',
    # TEQUILA / MEZCAL
    'Patron', 'JoseCuervo', 'DonJulio', 'Herradura', 'Espolon',
    'OlmecaAltos', 'Sauza', 'Tequila1800', 'Casamigos', 'ClaseAzul',
    'Hornitos', 'ElJimador', 'Cazadores', 'Teremana', 'Avion',
    'Milagro', 'Corralejo', 'DelMaguey',
    # RUM
    'Bacardi', 'CaptainMorgan', 'HavanaClub', 'Malibu', 'Kraken',
    'AppletonEstate', 'MountGay', 'Diplomatico', 'RonZacapa', 'Plantation',
    'Myerss', 'SailorJerry', 'Brugal', 'Goslings', 'FlorDeCana',
    'DonQ', 'Pyrat', 'Cruzan',
    # GIN
    'BombaySapphire', 'Tanqueray', 'Gordons', 'Beefeater', 'Hendricks',
    'SeagramsGin', 'Plymouth', 'RokuGin', 'TheBotanist', 'Monkey47',
    'Bulldog', 'Gilbeys', 'Aviation', 'Nolets', 'Sipsmith',
    # COGNAC / BRANDY
    'Hennessy', 'RemyMartin', 'Martell', 'Courvoisier', 'Camus',
    'Hine', 'Meukow', 'StRemy', 'Torres', 'Metaxa',
    # LIQUEUR
    'Jagermeister', 'Baileys', 'Kahlua', 'Cointreau', 'GrandMarnier',
    'Disaronno', 'Campari', 'Aperol', 'Frangelico', 'Chambord',
    'Midori', 'SouthernComfort', 'Drambuie', 'Galliano', 'TiaMaria',
    'Amarula', 'FernetBranca', 'Ricard', 'Pernod', 'Chartreuse',
    'StGermain', 'Hpnotiq',
    # CHAMPAGNE
    'MoetChandon', 'DomPerignon', 'VeuveClicquot', 'Krug', 'Cristal', 'AceOfSpades',
    # ASIAN SPIRITS
    'Jinro', 'ChumChurum', 'Moutai', 'Wuliangye', 'Kubota', 'Dassai'
]

# ==========================================
# JSON DATABASE HELPERS
# ==========================================

def load_db() -> dict:
    """Load semua data dari file JSON."""
    if not os.path.exists(DB_PATH):
        return {"licenses": {}}
    try:
        with open(DB_PATH, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {"licenses": {}}

def save_db(data: dict):
    """Simpan data ke file JSON."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with open(DB_PATH, 'w') as f:
        json.dump(data, f, indent=2)

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def hash_hwid(hwid: str) -> str:
    return hashlib.sha256(hwid.encode('utf-8')).hexdigest()

def generate_license_key() -> str:
    """Generate unique license key dengan format DTC_Brand_hex."""
    db = load_db()
    existing_keys = set(db["licenses"].keys())
    while True:
        brand = secrets.choice(ALCOHOL_BRANDS)
        random_hex = secrets.token_hex(6)
        key = f"DTC_{brand}_{random_hex}"
        if len(key) > 40:
            key = key[:40]
        if key not in existing_keys:
            return key

def calculate_expires_at(duration_type: str, start_time: datetime):
    """Hitung waktu kadaluarsa. Return ISO string atau None jika lifetime."""
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
    """Parse ISO string ke datetime timezone-aware (UTC)."""
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TIMEZONE)
    return dt

# ==========================================
# ROUTES — WEBSITE (dari app.py Vercel lama)
# ==========================================

@app.route('/')
def index():
    # Coba render template HTML jika ada, fallback ke plain text
    try:
        return render_template('index.html')
    except Exception:
        return "PB Macro License Server is Running!", 200

@app.route('/download')
def download_file():
    filename = "PBMacro.exe"
    return send_from_directory(app.config['DOWNLOAD_FOLDER'], filename)

# ==========================================
# ROUTES — API LICENSE (dari app.py PythonAnywhere)
# ==========================================

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    try:
        data = request.get_json()
        if not data or 'duration_type' not in data:
            return jsonify({"success": False, "message": "Missing duration_type"}), 400

        duration_type = data['duration_type']
        valid_types = ['lifetime', '2weeks', '1month', 'demo_1min', 'trial_6hours']
        if duration_type not in valid_types:
            return jsonify({
                "success": False,
                "message": f"Invalid duration_type. Valid: {valid_types}"
            }), 400

        license_key = generate_license_key()
        created_at = datetime.now(TIMEZONE).isoformat()

        db = load_db()
        db["licenses"][license_key] = {
            "license_key": license_key,
            "hwid": None,
            "duration_type": duration_type,
            "created_at": created_at,
            "expires_at": None,   # Diisi saat aktivasi pertama
            "is_active": True,
            "last_used": None
        }
        save_db(db)

        return jsonify({
            "success": True,
            "license_key": license_key,
            "duration_type": duration_type,
            "message": "License generated. Duration starts upon first activation."
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
        hwid_hash   = hash_hwid(hwid)
        current_time = datetime.now(TIMEZONE)

        db = load_db()

        # Case-insensitive search
        matched_key = None
        for k in db["licenses"]:
            if k.lower() == license_key.lower():
                matched_key = k
                break

        if not matched_key:
            return jsonify({"success": False, "message": "Invalid Key"}), 404

        license = db["licenses"][matched_key]

        if not license["is_active"]:
            return jsonify({"success": False, "message": "EXPIRED: License Inactive"}), 403

        stored_hwid    = license["hwid"]
        expires_at_str = license["expires_at"]

        # --- AKTIVASI PERTAMA: Bind HWID + set expires ---
        if stored_hwid is None:
            new_expires = calculate_expires_at(license["duration_type"], current_time)
            license["hwid"]       = hwid_hash
            license["expires_at"] = new_expires
            license["last_used"]  = current_time.isoformat()
            stored_hwid    = hwid_hash
            expires_at_str = new_expires
            db["licenses"][matched_key] = license
            save_db(db)

        elif stored_hwid != hwid_hash:
            return jsonify({"success": False, "message": "HWID Mismatch"}), 403

        # --- CEK EXPIRY ---
        if expires_at_str:
            expires_at = parse_dt(expires_at_str)
            if current_time > expires_at:
                license["is_active"] = False
                db["licenses"][matched_key] = license
                save_db(db)
                return jsonify({"success": False, "message": "EXPIRED: Duration Ended"}), 403

        # Update last_used
        license["last_used"] = current_time.isoformat()
        db["licenses"][matched_key] = license
        save_db(db)

        return jsonify({
            "success": True,
            "message": "Valid",
            "duration": license["duration_type"],
            "expires_at": expires_at_str if expires_at_str else "Never"
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Server Error: {str(e)}"}), 500


@app.route('/api/licenses', methods=['GET'])
def list_licenses():
    try:
        db = load_db()
        result = []
        for key, lic in db["licenses"].items():
            result.append({
                "license_key": lic["license_key"],
                "hwid": (lic["hwid"][:8] + "...") if lic["hwid"] else "Unbound",
                "duration": lic["duration_type"],
                "active": lic["is_active"],
                "expires": lic["expires_at"] if lic["expires_at"] else "Never"
            })
        # Urutkan terbaru dulu
        result.sort(key=lambda x: x["license_key"], reverse=True)
        return jsonify({"licenses": result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/license/<license_key>/reset-hwid', methods=['POST'])
def reset_hwid(license_key):
    try:
        db = load_db()

        matched_key = None
        for k in db["licenses"]:
            if k.lower() == license_key.lower():
                matched_key = k
                break

        if not matched_key:
            return jsonify({"success": False, "message": "Key not found"}), 404

        db["licenses"][matched_key]["hwid"] = None
        save_db(db)
        return jsonify({"success": True, "message": "HWID reset successfully"}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/license/<license_key>/deactivate', methods=['POST'])
def deactivate_license(license_key):
    """Endpoint bonus: nonaktifkan lisensi secara manual."""
    try:
        db = load_db()

        matched_key = None
        for k in db["licenses"]:
            if k.lower() == license_key.lower():
                matched_key = k
                break

        if not matched_key:
            return jsonify({"success": False, "message": "Key not found"}), 404

        db["licenses"][matched_key]["is_active"] = False
        save_db(db)
        return jsonify({"success": True, "message": "License deactivated"}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ==========================================
# ENTRY POINT
# ==========================================

# Untuk Vercel (WSGI handler)
application = app

# Untuk local development
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)