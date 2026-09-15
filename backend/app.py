from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
from flask_cors import CORS
from flasgger import Swagger
from datetime import datetime
import database as db
import predictor as pr
import smtplib
import threading
import re
from urllib.parse import unquote
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
 
 
app = Flask(__name__)
CORS(app)
 
app.config['SWAGGER'] = {
    'title': '🛡️ IDS SHIELD API',
    'description': 'API REST du systeme de detection d\'intrusion reseau.',
    'version': '2.1.0',
    'uiversion': 3,
}
swagger = Swagger(app)
 
db.init_db()
ids = pr.IDSPredictor()
 
 

SQL_INJECTION = [
    r"('|%27|\")\s*(or|and)\s+('|%27|\")?\s*\w+\s*('|%27|\")?\s*=\s*('|%27|\")?\s*\w+",
    r"\bunion\b\s+\bselect\b",
    r"\b(select|insert|update|delete|drop)\b\s+\b(from|into|table|database)\b",
    r"--\s",
    r";\s*(drop|delete|update|insert)\b",
    r"\bsleep\s*\(\s*\d+\s*\)",
    r"\bbenchmark\s*\(",
    r"\bwaitfor\s+delay\b",
    r"('|%27|\")\s*(or|and)\s+('|%27|\")?\s*\d",
]

XSS = [
    r"<\s*script[^>]*>",
    r"javascript\s*:",
    r"\bon(error|load|click|mouseover)\s*=",
    r"<\s*img[^>]+src\s*=",
    r"\balert\s*\(",
    r"document\.cookie",
]

PATH_TRAVERSAL = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e[/\\]",
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:\\+windows",
    r"/proc/self/environ",
]

COMMAND_INJECTION = [
    r";\s*(ls|cat|rm|wget|curl|nc|bash|sh|id|whoami|uname)\b",
    r"\|\s*(ls|cat|rm|wget|curl|nc|bash|sh|id|whoami)\b",
    r"&&\s*(ls|cat|rm|wget|curl|nc|bash|sh)\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"/bin/(ba|z|c)?sh\b",
    r"\bcmd\.exe\b",
    r"\bpowershell\b",
    r"\bnc\s+-[a-z]*e\b",
]

SCANNER_PATHS = [
    r"/wp-admin", r"/wp-login", r"/phpmyadmin", r"/pma\b",
    r"/\.env\b", r"/\.git", r"/\.svn", r"/admin\b",
    r"/administrator", r"/manager/html", r"/cgi-bin",
    r"/shell", r"/backup", r"/config\.", r"/\.aws",
]
 

SCANNER_AGENTS = [
    "nmap", "nikto", "sqlmap", "dirb", "dirbuster", "gobuster",
    "wpscan", "masscan", "zgrab", "nessus", "openvas",
    "acunetix", "burpsuite", "hydra", "metasploit",
]
 
DOS_COUNT_THRESHOLD = 100
PROBE_PATHS_THRESHOLD = 8
 
 
def _compile_signatures(patterns):
    return [re.compile(p, re.IGNORECASE) for p in patterns]
 
 
_SIG_SQL = _compile_signatures(SQL_INJECTION)
_SIG_XSS = _compile_signatures(XSS)
_SIG_TRAVERSAL = _compile_signatures(PATH_TRAVERSAL)
_SIG_CMD = _compile_signatures(COMMAND_INJECTION)
_SIG_SCAN_PATHS = _compile_signatures(SCANNER_PATHS)
 
 
def _signature_hit(family, name, confidence):
    return {
        'matched': True,
        'family': family,
        'signature_name': name,
        'confidence': float(confidence),
    }
 
 
def analyze_signatures(method, path, body, user_agent, count=0, unique_paths=0):
    target = unquote(f"{path} {body}").lower()
    ua = (user_agent or "").lower()
 
    for rx in _SIG_CMD:
        if rx.search(target):
            return _signature_hit('u2r', 'Injection de commande (RCE)', 96)
 
    for rx in _SIG_TRAVERSAL:
        if rx.search(target):
            return _signature_hit('u2r', 'Traversee de repertoire', 94)
 
    for rx in _SIG_SQL:
        if rx.search(target):
            return _signature_hit('r2l', 'Injection SQL', 95)
 
    for rx in _SIG_XSS:
        if rx.search(target):
            return _signature_hit('r2l', 'Cross-Site Scripting (XSS)', 92)
 
    for agent in SCANNER_AGENTS:
        if agent in ua:
            return _signature_hit('probe', f'Outil de scan ({agent})', 93)
 
    for rx in _SIG_SCAN_PATHS:
        if rx.search(target):
            return _signature_hit('probe', 'Acces a un chemin sensible', 85)
 
    if unique_paths >= PROBE_PATHS_THRESHOLD:
        return _signature_hit('probe', 'Enumeration de chemins (scan)', 88)
 
    if count >= DOS_COUNT_THRESHOLD:
        return _signature_hit('dos', 'Saturation par volume de requetes', 90)
 
    return {'matched': False, 'family': None, 'signature_name': None, 'confidence': 0.0}
 
 
def combine_verdicts(ml_result, sig_result):
    if sig_result['matched']:
        return {
            'detection': 'ATTACK',
            'attack_type': sig_result['family'],
            'conf_det': sig_result['confidence'],
            'conf_cls': sig_result['confidence'],
            'detected_by': 'signature',
            'signature_name': sig_result['signature_name'],
        }
    return {
        'detection': ml_result['detection'],
        'attack_type': ml_result.get('attack_type'),
        'conf_det': ml_result['conf_det'],
        'conf_cls': ml_result.get('conf_cls', 100.0),
        'detected_by': 'ml',
        'signature_name': None,
    }
 
 
# Configuration Mailtrap
SMTP_SERVER = "sandbox.smtp.mailtrap.io"
SMTP_PORT = 2525
SMTP_USERNAME = "752df0e39677ef"
SMTP_PASSWORD = "e22850d8ea699a"
EMAIL_FROM = "ids_shield@alerts.com"
EMAIL_TO = "admin@idsshield.tn"
 
recent_attacks_buffer = []
MAX_BUFFER_SIZE = 50
 
 
def send_attack_alert(detection):
    try:
        attack_type = (detection.get('attack_type') or 'INCONNUE').upper()
        timestamp = detection.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        src_ip = detection.get('src_ip', 'inconnue')
        protocol = detection.get('protocol', 'tcp')
        service = detection.get('service', 'http')
        conf_det = detection.get('conf_det', 0)
        method = detection.get('method', 'GET')
        path = detection.get('path', '/')
        detected_by = detection.get('detected_by', 'ml')
        signature_name = detection.get('signature_name')
 
        if detected_by == 'signature' and signature_name:
            moteur = f"Moteur de signatures - {signature_name}"
        else:
            moteur = "Modele Machine Learning (XGBoost)"
 
        subject = f"🚨 IDS SHIELD - Attaque {attack_type} detectee"
 
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"></head>
        <body style="font-family: Arial, sans-serif; background:#0a0e1a; color:#e0e6f0; padding:30px;">
            <div style="max-width:600px; margin:auto; background:#11182c; border:2px solid #ff4757; border-radius:10px; padding:25px;">
                <h1 style="color:#ff4757; margin:0 0 10px 0;">🚨 ALERTE DE SECURITE</h1>
                <p style="color:#6b7a99; margin:0 0 25px 0;">Systeme IDS SHIELD - Detection automatique</p>
 
                <div style="background:#0a0e1a; border-left:4px solid #ff4757; padding:15px; margin-bottom:20px;">
                    <h2 style="color:#ff4757; margin:0 0 10px 0;">🚨 Type d'attaque : {attack_type}</h2>
                    <p style="margin:0; color:#fff; font-size:14px;">Niveau d'alerte : <strong>ELEVE</strong></p>
                </div>
 
                <h3 style="color:#00d4ff; margin:20px 0 10px 0;">Details de l'attaque</h3>
                <table style="width:100%; border-collapse:collapse; color:#e0e6f0;">
                    <tr><td style="padding:8px; border-bottom:1px solid #1e2a45; width:30%;"><strong>Horodatage</strong></td><td style="padding:8px; border-bottom:1px solid #1e2a45;">{timestamp}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #1e2a45;"><strong>IP Source</strong></td><td style="padding:8px; border-bottom:1px solid #1e2a45;"><code style="color:#ff4757;">{src_ip}</code></td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #1e2a45;"><strong>Protocole</strong></td><td style="padding:8px; border-bottom:1px solid #1e2a45;">{protocol.upper()}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #1e2a45;"><strong>Service</strong></td><td style="padding:8px; border-bottom:1px solid #1e2a45;">{service}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #1e2a45;"><strong>Methode HTTP</strong></td><td style="padding:8px; border-bottom:1px solid #1e2a45;">{method}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #1e2a45;"><strong>Path</strong></td><td style="padding:8px; border-bottom:1px solid #1e2a45;"><code>{path}</code></td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #1e2a45;"><strong>Moteur de detection</strong></td><td style="padding:8px; border-bottom:1px solid #1e2a45;">{moteur}</td></tr>
                </table>
 
                <div style="background:#1a2440; padding:15px; border-radius:6px; margin-top:25px; border-left:4px solid #f39c12;">
                    <p style="margin:0; color:#f39c12; font-size:13px;"><strong>Action recommandee :</strong></p>
                    <p style="margin:5px 0 0 0; color:#e0e6f0; font-size:12px;">Consultez le dashboard IDS SHIELD pour plus de details et examinez l'historique des activites provenant de cette IP source.</p>
                </div>
 
                <p style="color:#6b7a99; font-size:11px; margin-top:30px; text-align:center; border-top:1px solid #1e2a45; padding-top:15px;">
                    IDS SHIELD <br>
                    Machine Learning (XGBoost / NSL-KDD)<br>
                    PFE Licence Genie Logiciel 2026
                </p>
            </div>
        </body>
        </html>
        """
 
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        msg.attach(MIMEText(html_body, 'html'))
 
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
 
        print(f"  🚨 Email d'alerte envoye pour {attack_type} depuis {src_ip}")
 
    except Exception as e:
        print(f"  Erreur envoi email : {e}")
 
 
def add_to_buffer(detection):
    global recent_attacks_buffer
    recent_attacks_buffer.append(detection)
    if len(recent_attacks_buffer) > MAX_BUFFER_SIZE:
        recent_attacks_buffer = recent_attacks_buffer[-MAX_BUFFER_SIZE:]
 
 
@app.route('/')
def home():
    """
    Accueil
    ---
    tags:
      - Systeme
    responses:
      200:
        description: Backend operationnel
    """
    return jsonify({'status': 'ok', 'service': 'IDS SHIELD Backend', 'version': '2.1'})
 
 
@app.route('/api/log', methods=['POST'])
def api_log():
    """
    Recoit un log depuis le client_http_sniffer et le teste.
    ---
    tags:
      - Detection
    parameters:
      - in: body
        name: body
        required: true
        description: Log extrait du paquet HTTP par le client sniffer
    responses:
      200:
        description: Verdict du systeme (normal ou attack + details)
    """
    data = request.json or {}
 
    ml_result = ids.predict(data)
 
    sig_result = analyze_signatures(
        method=data.get('method', 'GET'),
        path=data.get('path', '/'),
        body=data.get('body', ''),
        user_agent=data.get('user_agent', ''),
        count=int(data.get('count', 0) or 0),
        unique_paths=int(data.get('unique_paths', 0) or 0),
    )
 
    final = combine_verdicts(ml_result, sig_result)
 
    det = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'detection': final['detection'],
        'attack_type': final['attack_type'],
        'protocol': ml_result['protocol'],
        'service': ml_result['service'],
        'conf_det': final['conf_det'],
        'conf_cls': final['conf_cls'],
        'src_bytes': ml_result['src_bytes'],
        'dst_bytes': ml_result['dst_bytes'],
        'detected_by': final['detected_by'],
        'src_ip': data.get('src_ip', 'inconnue'),
        'method': data.get('method', 'GET'),
        'path': data.get('path', '/'),
        'signature_name': final.get('signature_name'),
    }
 
    db.save_detection(det)
 
    if final['detection'] == 'ATTACK':
        threading.Thread(target=send_attack_alert, args=(det,), daemon=True).start()
        add_to_buffer(det)
 
    if final['detection'] == 'ATTACK':
        return jsonify({
            'status': 'blocked',
            'reason': (final.get('attack_type') or 'unknown').upper(),
            'detection': final['detection'],
            'attack_type': final.get('attack_type'),
            'conf_det': final['conf_det'],
            'confidence': final['conf_det'],
            'detected_by': final['detected_by'],
            'signature_name': final.get('signature_name'),
        })
    return jsonify({
        'status': 'ok',
        'detection': 'NORMAL',
        'conf_det': final['conf_det'],
        'detected_by': final['detected_by'],
    })
 
 
@app.route('/recent_attacks', methods=['GET'])
def recent_attacks():
    """
    Retourne les attaques recentes pour le systeme de popup du dashboard.
    ---
    tags:
      - Detection
    parameters:
      - in: query
        name: since
        type: string
        description: Timestamp ISO depuis lequel retourner les attaques
    responses:
      200:
        description: Liste des attaques recentes
    """
    since = request.args.get('since', '')
    if since:
        attacks = [a for a in recent_attacks_buffer if a['timestamp'] > since]
    else:
        attacks = recent_attacks_buffer[-10:]
    return jsonify(attacks)
 
 
@app.route('/predict', methods=['POST'])
def predict():
    """
    Analyse manuelle d'une connexion reseau
    ---
    tags:
      - Detection
    """
    data = request.json or {}
 
    ml_result = ids.predict(data)
 
    sig_result = analyze_signatures(
        method=data.get('method', 'GET'),
        path=data.get('path', '/'),
        body=data.get('body', ''),
        user_agent=data.get('user_agent', ''),
        count=int(data.get('count', 0) or 0),
        unique_paths=int(data.get('unique_paths', 0) or 0),
    )
 
    final = combine_verdicts(ml_result, sig_result)
 
    det = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'detection': final['detection'],
        'attack_type': final['attack_type'],
        'protocol': ml_result['protocol'],
        'service': ml_result['service'],
        'conf_det': final['conf_det'],
        'conf_cls': final['conf_cls'],
        'src_bytes': ml_result['src_bytes'],
        'dst_bytes': ml_result['dst_bytes'],
        'detected_by': final['detected_by'],
        'src_ip': 'manuel',
        'method': data.get('method', 'MANUAL'),
        'path': data.get('path', '/predict'),
        'signature_name': final.get('signature_name'),
    }
    db.save_detection(det)
 
    if final['detection'] == 'ATTACK':
        threading.Thread(target=send_attack_alert, args=(det,), daemon=True).start()
        add_to_buffer(det)
 
    return jsonify({
        'detection': final['detection'],
        'attack_type': final['attack_type'],
        'conf_det': final['conf_det'],
        'conf_cls': final['conf_cls'],
        'protocol': ml_result['protocol'],
        'service': ml_result['service'],
        'src_bytes': ml_result['src_bytes'],
        'dst_bytes': ml_result['dst_bytes'],
        'detected_by': final['detected_by'],
        'signature_name': final.get('signature_name'),
    })
 
 
@app.route('/simulate', methods=['POST'])
def simulate():
    """
    Simulation d'une attaque a partir d'un echantillon NSL-KDD.
    ---
    tags:
      - Detection
    """
    data = request.json or {}
    family = data.get('family', 'any')
    sample = ids.get_sample(family)
    result = ids.predict(sample)
    det = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'detection': result['detection'],
        'attack_type': result.get('attack_type'),
        'protocol': result['protocol'],
        'service': result['service'],
        'conf_det': result['conf_det'],
        'conf_cls': result.get('conf_cls', 100.0),
        'src_bytes': result['src_bytes'],
        'dst_bytes': result['dst_bytes'],
        'detected_by': 'ml',
        'src_ip': 'simulation',
        'method': 'SIM',
        'path': f'/simulate/{family}',
    }
    db.save_detection(det)
 
    if result['detection'] == 'ATTACK':
        threading.Thread(target=send_attack_alert, args=(det,), daemon=True).start()
        add_to_buffer(det)
 
    result['true_family'] = family
    result['detected_by'] = 'ml'
    result['sample_features'] = {k: str(v) for k, v in sample.items()}
    return jsonify(result)
 
 
@app.route('/history', methods=['GET'])
def history():
    limit = int(request.args.get('limit', 1000))
    return jsonify(db.get_detections(limit))
 
 
@app.route('/history/clear', methods=['POST'])
def clear_history():
    db.clear_detections()
    return jsonify({'status': 'ok', 'message': 'Historique vide'})
 
 
@app.route('/stats', methods=['GET'])
def stats():
    detections = db.get_detections(10000)
    total = len(detections)
    normal = sum(1 for d in detections if d['detection'] == 'NORMAL')
    attacks = total - normal
    by_family = {'dos': 0, 'probe': 0, 'r2l': 0, 'u2r': 0}
    for d in detections:
        if d['attack_type'] and d['attack_type'] in by_family:
            by_family[d['attack_type']] += 1
    by_proto = {}
    for d in detections:
        p = d['protocol']
        by_proto[p] = by_proto.get(p, 0) + 1
    by_service = {}
    for d in detections:
        s = d['service']
        by_service[s] = by_service.get(s, 0) + 1
    top_services = sorted(by_service.items(), key=lambda x: -x[1])[:5]
    attack_rate = round(100 * attacks / total, 1) if total > 0 else 0
    by_engine = {'ml': 0, 'signature': 0}
    for d in detections:
        eng = d.get('detected_by', 'ml')
        if eng in by_engine:
            by_engine[eng] += 1
    return jsonify({
        'total': total,
        'normal': normal,
        'attacks': attacks,
        'attack_rate': attack_rate,
        'by_family': by_family,
        'by_protocol': by_proto,
        'by_engine': by_engine,
        'top_services': [{'service': s, 'count': c} for s, c in top_services],
        'recent': detections[:10]
    })
 
 
@app.route('/profiles', methods=['GET'])
def list_profiles():
    """
    👥 Liste tous les profils
    ---
    tags:
      - Profils
    """
    return jsonify(db.get_profiles())
 
 
@app.route('/profiles', methods=['POST'])
def create_profile():
    """
    👥 Cree un nouveau profil
    ---
    tags:
      - Profils
    """
    data = request.json or {}
    required = ['code', 'nom', 'username', 'password']
    if not all(k in data for k in required):
        return jsonify({'error': 'Champs manquants'}), 400
    try:
        db.add_profile(data)
        return jsonify({'status': 'ok', 'message': 'Profil cree'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400
 
 
@app.route('/profiles/<code>', methods=['DELETE'])
def remove_profile(code):
    """
    👥 Supprime un profil
    ---
    tags:
      - Profils
    """
    db.delete_profile(code)
    return jsonify({'status': 'ok', 'message': f'Profil {code} supprime'})
 
 
@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    import sqlite3
    conn = sqlite3.connect(db.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM profiles WHERE username=?",
                   (username,)).fetchone()
    conn.close()
    if row and check_password_hash(row['password'], password):
        return jsonify({'status': 'ok', 'user': {
            'code': row['code'],
            'nom': row['nom'],
            'username': row['username']
        }})
    return jsonify({'error': 'Identifiants invalides'}), 401
 
 
if __name__ == '__main__':
    print("🛡️  IDS SHIELD")
    print(f"   API : http://localhost:5000")
    print(f"   Docs: http://localhost:5000/apidocs")
    app.run(host='0.0.0.0', port=5000, debug=False)