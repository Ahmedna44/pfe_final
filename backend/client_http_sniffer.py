import sys
import time
import json
import requests
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import defaultdict
import threading

# Adresse du serveur IDS et port d'écoute du sniffer
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
SERVER_URL = f"http://{SERVER_IP}:{SERVER_PORT}/api/log"

CLIENT_PORT = 8080
# Codes couleur pour l'affichage dans le terminal
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# Historique par IP (nb de requêtes, chemins visités) et verrou pour les accès simultanés
ip_history = defaultdict(lambda: {'count': 0, 'paths': set(), 'last_time': 0})
stats_lock = threading.Lock()

# Affiche la bannière de démarrage
def print_banner():
    print(Color.CYAN + Color.BOLD + "=" * 70 + Color.RESET)
    print(Color.CYAN + Color.BOLD + "  🛡️  IDS SHIELD - Sniffer HTTP" + Color.RESET)
    print(Color.CYAN + Color.BOLD + "=" * 70 + Color.RESET)
    print(f"  Serveur : {SERVER_URL}")
    print(f"  🌐 Port  : {CLIENT_PORT}")
    print(f"  Heure   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Color.CYAN + "=" * 70 + Color.RESET)
    print()

# Vérifie que le serveur IDS est accessible avant de démarrer
def test_server_connection():
    print(f"Test de connexion au serveur {SERVER_IP}:{SERVER_PORT}...")
    try:
        response = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/", timeout=3)
        if response.status_code in [200, 404]:
            print(Color.GREEN + "Serveur accessible !" + Color.RESET)
            return True
    except requests.exceptions.ConnectionError:
        print(Color.RED + "Serveur INACCESSIBLE !" + Color.RESET)
        print(Color.YELLOW + "   -> Lance d'abord le serveur : python app.py" + Color.RESET)
        return False
    except Exception as e:
        print(Color.RED + f"Erreur : {e}" + Color.RESET)
        return False
    return False

# Convertit la méthode HTTP en flag NSL-KDD (S0 ou SF)
def http_method_to_flag(method):
    if method in ['TRACE', 'CONNECT', 'DEBUG']:
        return 'S0'
    return 'SF'

# Devine le service NSL-KDD à partir du chemin de l'URL
def path_to_service(path):
    path_l = path.lower()
    if 'ftp' in path_l: return 'ftp'
    if 'ssh' in path_l: return 'ssh'
    if 'mail' in path_l or 'smtp' in path_l: return 'smtp'
    if 'sql' in path_l or 'mysql' in path_l: return 'sql'
    if 'admin' in path_l or 'login' in path_l: return 'http'
    return 'http'
# Construit les 41 caractéristiques NSL-KDD à partir de la requête HTTP reçue

def extract_log_from_packet(method, path, headers, body, client_ip):
    body_str = body if isinstance(body, str) else body.decode('utf-8', errors='ignore')

    with stats_lock:
        history = ip_history[client_ip]
        history['count'] += 1
        history['paths'].add(path)
        current_time = time.time()
        time_diff = current_time - history['last_time'] if history['last_time'] else 999
        history['last_time'] = current_time

        request_count = min(history['count'], 511)
        unique_paths = len(history['paths'])

    flag = http_method_to_flag(method)
    service = path_to_service(path)

    # Taux d'erreur base sur la frequence
    if request_count > 100 and time_diff < 0.5:
        error_rate = min(request_count / 200.0, 1.0)
    elif request_count > 30:
        error_rate = 0.3
    else:
        error_rate = 0.0

    if unique_paths > 5:
        diff_srv = min(unique_paths / 20.0, 1.0)
        same_srv = 1.0 - diff_srv
    else:
        diff_srv = 0.0
        same_srv = 1.0

    log = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': client_ip,
        'dst_ip': '127.0.0.1',
        'method': method,
        'path': path,

        'body': body_str,
        'user_agent': headers.get('User-Agent', ''),
        'unique_paths': unique_paths,

        'duration': 0,
        'protocol_type': 'tcp',
        'service': service,
        'flag': flag,
        'src_bytes': len(body_str) + len(path),
        'dst_bytes': 200,

        'count': request_count,
        'srv_count': request_count,
        'serror_rate': error_rate if flag == 'S0' else 0.0,
        'srv_serror_rate': error_rate if flag == 'S0' else 0.0,
        'rerror_rate': error_rate if flag == 'REJ' else 0.0,
        'srv_rerror_rate': error_rate if flag == 'REJ' else 0.0,
        'same_srv_rate': same_srv,
        'diff_srv_rate': diff_srv,
        'srv_diff_host_rate': 0.0,

        'dst_host_count': min(request_count, 255),
        'dst_host_srv_count': min(request_count, 255),
        'dst_host_same_srv_rate': same_srv,
        'dst_host_diff_srv_rate': diff_srv,
        'dst_host_same_src_port_rate': 1.0 if unique_paths < 5 else 0.3,
        'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': error_rate if flag == 'S0' else 0.0,
        'dst_host_srv_serror_rate': error_rate if flag == 'S0' else 0.0,
        'dst_host_rerror_rate': error_rate if flag == 'REJ' else 0.0,
        'dst_host_srv_rerror_rate': error_rate if flag == 'REJ' else 0.0,

        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 1,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
    }

    return log

# Envoie le log au serveur IDS et récupère le verdict
def send_log_to_server(log):
    try:
        response = requests.post(
            SERVER_URL,
            json=log,
            timeout=3,
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'HTTP {response.status_code}'}

    except requests.exceptions.Timeout:
        return {'error': 'timeout'}
    except requests.exceptions.ConnectionError:
        return {'error': 'connection_refused'}
    except Exception as e:
        return {'error': str(e)}

# Affiche le verdict dans le terminal, avec une couleur selon le type d'attaque
def display_verdict(log, verdict):
    timestamp = datetime.now().strftime('%H:%M:%S')
    src = log['src_ip'][:15]
    method = log['method']
    path = log['path'][:40]

    if 'error' in verdict:
        color = Color.DIM
        status = f"Erreur: {verdict['error']}"
    elif verdict.get('detection') == 'NORMAL':
        color = Color.GREEN
        status = "TRAFIC NORMAL"
    else:
        attack_type = (verdict.get('attack_type') or 'INCONNUE').upper()

        if attack_type == 'DOS':
            color = Color.RED
        elif attack_type == 'PROBE':
            color = Color.YELLOW
        elif attack_type in ['R2L', 'U2R']:
            color = Color.PURPLE
        else:
            color = Color.RED
        status = f"🚨 ATTAQUE DETECTEE - Type: {attack_type}"

    print(f"{Color.DIM}[{timestamp}]{Color.RESET} "
          f"{src:>15s} {Color.CYAN}{method:6s}{Color.RESET} "
          f"{path:<40s} {color}{status}{Color.RESET}")

# Compteurs globaux : paquets analysés et attaques détectées
packet_count = 0
attack_count = 0
# Serveur HTTP qui reçoit le trafic (logs internes désactivés)
class SnifferHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass
# Accepte toutes les méthodes HTTP (GET, POST...) et gère le CORS (OPTIONS)
    def handle_request(self, method):
        global packet_count, attack_count

        try:
            client_ip = self.client_address[0]
            path = self.path
            headers = dict(self.headers)

            body = ''
            content_length = int(headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length).decode('utf-8', errors='ignore')

            packet_count += 1

            log = extract_log_from_packet(method, path, headers, body, client_ip)

            verdict = send_log_to_server(log)

            if verdict.get('detection') == 'ATTACK':
                attack_count += 1

            display_verdict(log, verdict)

            if 'error' in verdict:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(verdict).encode())
            elif verdict.get('detection') == 'ATTACK':
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({
                    'status': 'blocked',
                    'reason': verdict.get('attack_type', 'Unknown'),
                    'confidence': verdict.get('conf_det', 0),
                    'detected_by': verdict.get('detected_by', 'ml'),
                    'signature_name': verdict.get('signature_name'),
                }).encode())
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'ok'}).encode())

        except Exception as e:
            print(Color.RED + f"Erreur : {e}" + Color.RESET)
            try:
                self.send_response(500)
                self.end_headers()
            except:
                pass

    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        self.handle_request('POST')

    def do_PUT(self):
        self.handle_request('PUT')

    def do_DELETE(self):
        self.handle_request('DELETE')

    def do_HEAD(self):
        self.handle_request('HEAD')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

# Lance le sniffer : teste le serveur puis écoute en boucle sur le port 8080
def main():
    print_banner()

    if not test_server_connection():
        print(Color.RED + "\nImpossible de continuer sans serveur." + Color.RESET)
        sys.exit(1)

    print()
    print(Color.GREEN + Color.BOLD +
          f"Sniffer demarre sur le port {CLIENT_PORT}" + Color.RESET)
    print()
    print("=" * 70)
    print(Color.BOLD + "  LIVE LOG - Ctrl+C pour arreter" + Color.RESET)
    print("=" * 70)
    print(f"  {'TIME':<10} {'SOURCE':>15s} {'METHOD':6s} {'PATH':<40s} VERDICT")
    print("-" * 70)

    try:
        server = HTTPServer(('0.0.0.0', CLIENT_PORT), SnifferHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print()
        print(Color.YELLOW + "=" * 70 + Color.RESET)
        print(Color.YELLOW + Color.BOLD + "  Sniffer arrete" + Color.RESET)
        print(Color.YELLOW + "=" * 70 + Color.RESET)
        print(f"  Paquets analyses   : {packet_count}")
        print(f"  🚨 Attaques detectees: {attack_count}")
        print(Color.YELLOW + "=" * 70 + Color.RESET)
        sys.exit(0)
    except OSError as e:
        if 'Address already in use' in str(e):
            print(Color.RED + f"\nLe port {CLIENT_PORT} est deja utilise !" + Color.RESET)
            print(Color.YELLOW + "   -> Ferme l'autre programme ou change CLIENT_PORT" + Color.RESET)
        else:
            print(Color.RED + f"\nErreur : {e}" + Color.RESET)
        sys.exit(1)
    except Exception as e:
        print(Color.RED + f"\nErreur : {e}" + Color.RESET)
        sys.exit(1)

# Point de démarrage du programme
if __name__ == '__main__':
    main()