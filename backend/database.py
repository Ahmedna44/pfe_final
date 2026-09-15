import sqlite3, os
from datetime import datetime
from werkzeug.security import generate_password_hash
# Emplacement du fichier de la base de données
DB_PATH = os.path.join(os.path.dirname(__file__), 'ids.db')
# Ouvre une connexion à la base (accès aux colonnes par leur nom)
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
# Initialise la base : crée les tables au démarrage
def init_db():
    conn = get_conn(); c = conn.cursor()
   
    # Table des détections (historique des analyse)
    c.execute('''CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, detection TEXT, attack_type TEXT,
        protocol TEXT, service TEXT, conf_det REAL, conf_cls REAL,
        src_bytes INTEGER, dst_bytes INTEGER, raw_features TEXT)''')
    
    det_cols = [row[1] for row in c.execute("PRAGMA table_info(detections)").fetchall()]
    if 'detected_by' not in det_cols:
        print("Migration : ajout de la colonne detected_by...")
        c.execute("ALTER TABLE detections ADD COLUMN detected_by TEXT DEFAULT 'ml'")
        conn.commit()
        print("Colonne detected_by ajoutee")
    # Met à jour une ancienne version de la table profiles
    has_profiles = c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='profiles'"
    ).fetchone() is not None
    if has_profiles:
        cols = [row[1] for row in c.execute("PRAGMA table_info(profiles)").fetchall()]
        if 'role' in cols:
            print("Migration : suppression du systeme multi-roles...")
            c.execute("DELETE FROM profiles WHERE role != 'admin'")
            c.execute('''CREATE TABLE profiles_new (
                code TEXT PRIMARY KEY, nom TEXT, username TEXT UNIQUE,
                password TEXT, created_at TEXT)''')
            c.execute('''INSERT INTO profiles_new (code, nom, username, password, created_at)
                         SELECT code, nom, username, password, created_at FROM profiles''')
            c.execute("DROP TABLE profiles")
            c.execute("ALTER TABLE profiles_new RENAME TO profiles")
            conn.commit()
            print("Systeme mono-administrateur active")
    # Table des comptes administrateurs
    c.execute('''CREATE TABLE IF NOT EXISTS profiles (
        code TEXT PRIMARY KEY, nom TEXT, username TEXT UNIQUE,
        password TEXT, created_at TEXT)''')
    # Crée un compte admin par défaut si la base est vide
    c.execute("SELECT COUNT(*) FROM profiles")
    if c.fetchone()[0] == 0:
        d = datetime.now().strftime('%Y-%m-%d')
        c.execute("INSERT INTO profiles VALUES (?,?,?,?,?)",
          ('ADM001', 'Administrateur', 'admin', generate_password_hash('admin123'), d))
    # Enregistre les changements et ferme la base
    conn.commit(); conn.close()
    print("Base de donnees initialisee")
# Enregistre une détection dans la base
def save_detection(d):
    conn = get_conn()
    conn.execute('''INSERT INTO detections
        (timestamp,detection,attack_type,protocol,service,conf_det,conf_cls,src_bytes,dst_bytes,raw_features,detected_by)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (d['timestamp'], d['detection'], d.get('attack_type'), d['protocol'], d['service'],
         d['conf_det'], d.get('conf_cls', 100.0), d.get('src_bytes', 0),
         d.get('dst_bytes', 0), d.get('raw_features', ''), d.get('detected_by', 'ml')))
    conn.commit(); conn.close()
# Récupère les dernières détections
def get_detections(limit=1000):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM detections ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
# Vide tout l'historique des détections
def clear_detections():
    conn = get_conn(); conn.execute("DELETE FROM detections"); conn.commit(); conn.close()
# Récupère la liste des comptes admin (sans le mot de passe)
def get_profiles():
    conn = get_conn()
    rows = conn.execute("SELECT code,nom,username,created_at FROM profiles").fetchall()
    conn.close()
    return [dict(r) for r in rows]
# Ajoute un nouveau compte administrateur
def add_profile(p):
    conn = get_conn()
    conn.execute("INSERT INTO profiles VALUES (?,?,?,?,?)",
             (p['code'], p['nom'], p['username'], generate_password_hash(p['password']),
              datetime.now().strftime('%Y-%m-%d')))
    conn.commit(); conn.close()
# Supprime un compte admin
def delete_profile(code):
    conn = get_conn(); conn.execute("DELETE FROM profiles WHERE code=?", (code,))
    conn.commit(); conn.close()