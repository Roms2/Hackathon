from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import pandas as pd
import joblib
from datetime import datetime

app = FastAPI()

# Charger le modèle de Machine Learning
MODEL_PATH = "model.pkl"  
model = joblib.load(MODEL_PATH)

# Connexion à la base de données SQLite
DB_PATH = "network_traffic.db"

def init_db():
    """Créer la base de données et la table si elles n'existent pas."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            duration REAL,
            protocol_type TEXT,
            service TEXT,
            flag TEXT,
            src_bytes INTEGER,
            dst_bytes INTEGER,
            count INTEGER,
            serror_rate REAL,
            rerror_rate REAL,
            same_srv_rate REAL,
            back INTEGER,
            buffer_overflow INTEGER,
            ftp_write INTEGER,
            guess_passwd INTEGER,
            imap INTEGER,
            ipsweep INTEGER,
            land INTEGER,
            loadmodule INTEGER,
            multihop INTEGER,
            neptune INTEGER,
            nmap INTEGER,
            normal INTEGER,
            perl INTEGER,
            phf INTEGER,
            pod INTEGER,
            portsweep INTEGER,
            rootkit INTEGER,
            satan INTEGER,
            smurf INTEGER,
            spy INTEGER,
            teardrop INTEGER,
            warezclient INTEGER,
            warezmaster INTEGER,
            label TEXT,  -- Normal ou type d'attaque détecté
            anomaly INTEGER  -- 0 = Normal, 1 = Anomalie
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Définition du format des données reçues
class NetworkConnection(BaseModel):
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: int
    dst_bytes: int
    count: int
    serror_rate: float
    rerror_rate: float
    same_srv_rate: float
    back: int
    buffer_overflow: int
    ftp_write: int
    guess_passwd: int
    imap: int
    ipsweep: int
    land: int
    loadmodule: int
    multihop: int
    neptune: int
    nmap: int
    normal: int
    perl: int
    phf: int
    pod: int
    portsweep: int
    rootkit: int
    satan: int
    smurf: int
    spy: int
    teardrop: int
    warezclient: int
    warezmaster: int
    label: str  # Normal ou attaque spécifique

def preprocess_data(data: dict):
    """
    Prépare les données pour le modèle IA :
    - Convertit les catégories en valeurs numériques
    - Normalise les valeurs si nécessaire
    """
    protocol_map = {"tcp": 0, "udp": 1, "icmp": 2}
    service_map = {"http": 0, "ftp": 1, "smtp": 2, "dns": 3, "other": 4}
    flag_map = {"SF": 0, "REJ": 1, "S0": 2, "RSTO": 3, "OTH": 4}

    processed_data = {
        "duration": data["duration"],
        "protocol_type": protocol_map.get(data["protocol_type"], -1),
        "service": service_map.get(data["service"], -1),
        "flag": flag_map.get(data["flag"], -1),
        "src_bytes": data["src_bytes"],
        "dst_bytes": data["dst_bytes"],
        "count": data["count"],
        "serror_rate": data["serror_rate"],
        "rerror_rate": data["rerror_rate"],
        "same_srv_rate": data["same_srv_rate"],
    }

    # Ajouter les colonnes spécifiques (back, buffer_overflow, etc.)
    attack_labels = [
        "back", "buffer_overflow", "ftp_write", "guess_passwd", "imap", "ipsweep", "land", "loadmodule", 
        "multihop", "neptune", "nmap", "normal", "perl", "phf", "pod", "portsweep", "rootkit", "satan", 
        "smurf", "spy", "teardrop", "warezclient", "warezmaster"
    ]
    
    for label in attack_labels:
        processed_data[label] = data[label]

    return pd.DataFrame([processed_data])

@app.post("/send_data")
async def receive_data(connection: NetworkConnection):
    """Reçoit les données brutes, les prétraite, les stocke en BDD et les envoie au modèle ML."""
    log_entry = connection.dict()
    log_entry["timestamp"] = datetime.utcnow().isoformat()

    # Prétraitement
    processed_df = preprocess_data(log_entry)

    # Prédiction avec le modèle ML
    anomaly_prediction = model.predict(processed_df)[0]  
    log_entry["anomaly"] = int(anomaly_prediction)

    # Sauvegarde en BDD
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO connections 
        (timestamp, duration, protocol_type, service, flag, src_bytes, dst_bytes, count, serror_rate, 
         rerror_rate, same_srv_rate, back, buffer_overflow, ftp_write, guess_passwd, imap, ipsweep, land, 
         loadmodule, multihop, neptune, nmap, normal, perl, phf, pod, portsweep, rootkit, satan, smurf, spy, 
         teardrop, warezclient, warezmaster, label, anomaly)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log_entry["timestamp"], log_entry["duration"], log_entry["protocol_type"], log_entry["service"], 
        log_entry["flag"], log_entry["src_bytes"], log_entry["dst_bytes"], log_entry["count"], 
        log_entry["serror_rate"], log_entry["rerror_rate"], log_entry["same_srv_rate"],
        log_entry["back"], log_entry["buffer_overflow"], log_entry["ftp_write"], log_entry["guess_passwd"],
        log_entry["imap"], log_entry["ipsweep"], log_entry["land"], log_entry["loadmodule"], log_entry["multihop"],
        log_entry["neptune"], log_entry["nmap"], log_entry["normal"], log_entry["perl"], log_entry["phf"],
        log_entry["pod"], log_entry["portsweep"], log_entry["rootkit"], log_entry["satan"], log_entry["smurf"],
        log_entry["spy"], log_entry["teardrop"], log_entry["warezclient"], log_entry["warezmaster"],
        log_entry["label"], log_entry["anomaly"]
    ))
    conn.commit()
    conn.close()

    return {"message": "Données traitées et stockées", "data": log_entry}
