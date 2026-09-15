# Librairies
import joblib, os
import numpy as np
import pandas as pd
import xgboost as xgb
 # Chemins vers les dossiers des modèles et des données brutes
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'raw')
 # Les 41 caractéristiques de NSL-KDD, dans l'ordre attendu par le modèle
COL_NAMES = ["duration","protocol_type","service","flag","src_bytes","dst_bytes",
 "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
 "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
 "num_shells","num_access_files","num_outbound_cmds","is_host_login",
 "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
 "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
 "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
 "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
 "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
 "dst_host_rerror_rate","dst_host_srv_rerror_rate"]
 # Colonnes catégorielles à encoder, et noms des 5 familles
CAT_VARS = ['protocol_type','service','flag','land','logged_in','is_host_login','is_guest_login']
CLASS_NAMES_5 = ['Normal','DoS','Probe','R2L','U2R']
# Correspondance entre chaque nom d'attaque et sa famille
ATTACK_FAMILY_MAP = {
 'normal':'normal',
 'back':'dos','land':'dos','neptune':'dos','pod':'dos','smurf':'dos','teardrop':'dos',
 'apache2':'dos','mailbomb':'dos','processtable':'dos','udpstorm':'dos',
 'ipsweep':'probe','nmap':'probe','portsweep':'probe','satan':'probe','mscan':'probe','saint':'probe',
 'ftp_write':'r2l','guess_passwd':'r2l','imap':'r2l','multihop':'r2l','phf':'r2l','spy':'r2l',
 'warezclient':'r2l','warezmaster':'r2l','sendmail':'r2l','named':'r2l','snmpgetattack':'r2l',
 'snmpguess':'r2l','xlock':'r2l','xsnoop':'r2l','worm':'r2l',
 'buffer_overflow':'u2r','loadmodule':'u2r','perl':'u2r','rootkit':'u2r',
 'httptunnel':'u2r','ps':'u2r','sqlattack':'u2r','xterm':'u2r'}
 # Classe regroupant les modèles et la logique de prédiction
class IDSPredictor:
    # Chargement des modèles et des données au démarrage (une seule fois)
    def __init__(self):
        print("Chargement des modeles")
        self.model_binary = joblib.load(os.path.join(MODELS_DIR, 'model_binary.pkl'))
        self.model_multi = joblib.load(os.path.join(MODELS_DIR, 'model_multiclass.pkl'))
        self.scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
        self.feature_cols = joblib.load(os.path.join(MODELS_DIR, 'feature_cols.pkl'))
        self.metadata = joblib.load(os.path.join(MODELS_DIR, 'metadata.pkl'))
        # KDDTest+ pour les simulations
        cols = COL_NAMES + ['label', 'difficulty']
        self.ref_df = pd.read_csv(os.path.join(DATA_DIR, 'KDDTest+.txt'), header=None, names=cols)
        self.ref_df['family'] = self.ref_df['label'].map(ATTACK_FAMILY_MAP)
        print(f"Modeles charges ({len(self.feature_cols)} features)")
# Met les données au format attendu : encodage, ordre des colonnes, normalisation
    def _prepare_features(self, raw_df):
        df = raw_df[COL_NAMES].copy()
        cat_data = pd.get_dummies(df[CAT_VARS]).astype(int)
        numeric = df[[c for c in df.columns if c not in CAT_VARS]].copy()
        combined = pd.concat([numeric, cat_data], axis=1)
        combined = combined.reindex(columns=self.feature_cols, fill_value=0)
        return self.scaler.transform(combined.values).astype(np.float32)
# Prédiction : on part des 41 features à 0, puis on applique les valeurs reçues
    def predict(self, raw_features):
        defaults = {c: 0 for c in COL_NAMES}
        defaults.update({'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF'})
        defaults.update(raw_features)
        df = pd.DataFrame([defaults])
        dX = xgb.DMatrix(self._prepare_features(df))
 # Modèle 1
        prob_bin = float(self.model_binary.predict(dX)[0])
        is_attack = prob_bin > 0.3
        conf_det = prob_bin * 100 if is_attack else (1 - prob_bin) * 100
# Construction du verdict (détection, confiance, infos de la connexion)
        result = {
            'detection': 'ATTACK' if is_attack else 'NORMAL',
            'conf_det': round(conf_det, 2),
            'protocol': defaults['protocol_type'],
            'service': defaults['service'],
            'src_bytes': int(defaults.get('src_bytes', 0)),
            'dst_bytes': int(defaults.get('dst_bytes', 0)),
        }
# Si attaque : le modèle 2 identifie la famille (on ignore la classe Normal)
        if is_attack:
            probs = self.model_multi.predict(dX)[0][1:]
            cls_idx = int(np.argmax(probs)) + 1
            result['attack_type'] = CLASS_NAMES_5[cls_idx].lower()
            result['conf_cls'] = round(float(probs[cls_idx - 1]) * 100, 2)
        else:
            result['attack_type'] = None
            result['conf_cls'] = round((1 - prob_bin) * 100, 2)
        return result
 # Tire une vraie connexion du dataset de test (utilisé par les simulations)
    def get_sample(self, family=None):
        if family and family != 'any':
            cand = self.ref_df[self.ref_df['family'] == family.lower()]
        else:
            cand = self.ref_df
        if len(cand) == 0: cand = self.ref_df
        row = cand.sample(1).iloc[0]
        return {col: row[col] for col in COL_NAMES}