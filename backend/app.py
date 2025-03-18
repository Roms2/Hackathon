from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import pandas as pd
import joblib
from datetime import datetime
import os
import time
import threading
from process import preprocess_data  # Fonction qui traite le fichier et retourne les données


# ------------------------ 1️⃣ 🚀 INITIALISATION VARIABLES ------------------------

DB_PATH = "network_traffic.db"

MODEL_PATH = "model.pkl"
model = joblib.load(MODEL_PATH)

WATCHED_FOLDER = "watched_folder/"


# ------------------------ 2️⃣ 🗄️ INITIALISATION BDD ------------------------

def init_db():
    """
    Initialise la base de données SQLite en créant la table `connections` si elle n’existe pas.
    """
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
            label TEXT,
            anomaly INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()  # Initialisation au démarrage


# ------------------------ 3️⃣ 👀 SURVEILLANCE TEMPS RÉEL ------------------------

def watch_and_process():
    """
    Surveille un dossier en temps réel, détecte le fichier le plus récent,
    l'envoie à la fonction process_file(), stocke les données traitées en BDD,
    puis supprime le fichier après traitement.
    """
    while True:
        try:
            # Liste tous les fichiers du dossier
            files = [f for f in os.listdir(WATCHED_FOLDER) if os.path.isfile(os.path.join(WATCHED_FOLDER, f))]
            
            if files:
                # Trouver le fichier le plus récent
                latest_file = min(files, key=lambda f: os.path.getctime(os.path.join(WATCHED_FOLDER, f)))
                file_path = os.path.join(WATCHED_FOLDER, latest_file)
                
                print(f"📂 Nouvelle alerte détectée : {latest_file}")
                # Charger le fichier en DataFrame 
                df = pd.read_csv(file_path, delimiter=",")  # Adapter le délimiteur si nécessaire
                processed_data = preprocess_data(df)  # Envoyer le DataFrame à process_file()
                # Traiter le fichier avec la fonction process_file() (retourne un dataframe ou une liste de tuples)
                
                if processed_data:
                    # Connexion à la base de données
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    
                    # Insérer chaque ligne de données traitées dans la BDD
                    if isinstance(processed_data, list):  # Vérifie que les données sont bien sous forme de liste unique
                        cursor.execute("""
                            INSERT INTO connections 
                            (timestamp, duration, protocol_type, service, flag, src_bytes, dst_bytes, count, serror_rate, 
                            rerror_rate, same_srv_rate, back, buffer_overflow, ftp_write, guess_passwd, imap, ipsweep, land, 
                            loadmodule, multihop, neptune, nmap, normal, perl, phf, pod, portsweep, rootkit, satan, smurf, spy, 
                            teardrop, warezclient, warezmaster, label, anomaly)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            datetime.utcnow().isoformat(),  # Timestamp
                            *processed_data  # Insère directement la seule ligne de données
                        ))

                    conn.commit()
                    conn.close()
                    print(f"✅ Données de {latest_file} insérées en BDD")


                # Supprimer le fichier après traitement
                os.remove(file_path)
                print(f"🗑️ Fichier supprimé : {latest_file}")

            # Pause avant la prochaine vérification
            time.sleep(3)  # Vérifie toutes les 5 secondes

        except Exception as e:
            print(f"⚠️ Erreur dans la surveillance du dossier : {e}")
            time.sleep(3)  # Pause pour éviter une boucle d'erreur infinie


# ------------------------ 📡 4️⃣  API FASTAPI (Réponse au Frontend) ------------------------

app = FastAPI()

from fastapi import FastAPI, Query
import sqlite3

app = FastAPI()

DB_PATH = "database.db"

@app.get("/get_data")
def get_data(
    table: str,                          # Nom de la table à interroger
    filter_column: str = None,           # Colonne à filtrer
    filter_value: str = None,            # Valeur du filtre
    sort_by: str = None,                 # Colonne pour trier les résultats
    order: str = "asc",                  # "asc" (croissant) ou "desc" (décroissant)
    limit: int = Query(10, gt=0),        # Nombre max de résultats à afficher (pagination)
    offset: int = Query(0, ge=0)         # Décalage pour la pagination
):
    """
    API GET universelle pour récupérer des données depuis une base SQLite.
    - `table` : Nom de la table (ex: "users", "anomalies").
    - `filter_column` : Colonne pour appliquer un filtre.
    - `filter_value` : Valeur du filtre.
    - `sort_by` : Colonne de tri.
    - `order` : "asc" pour croissant, "desc" pour décroissant.
    - `limit` : Nombre max de résultats.
    - `offset` : Décalage pour la pagination.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Base de la requête SQL
        query = f"SELECT * FROM {table}"
        params = []

        # Ajout d'un filtre si spécifié
        if filter_column and filter_value:
            query += f" WHERE {filter_column} = ?"
            params.append(filter_value)

        # Ajout du tri si spécifié
        if sort_by:
            query += f" ORDER BY {sort_by} {order.upper()}"

        # Ajout de la pagination
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        results = cursor.fetchall()

        conn.close()
        return {"table": table, "data": results}

    except Exception as e:
        return {"error": str(e)}


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
    label: str

# ------------------------ 5️⃣ 🚀 DÉMARRAGE AUTOMATIQUE AVEC MULTITHREADING ------------------------


if __name__ == "__main__":
    thread = threading.Thread(target=watch_and_process, daemon=True)
    thread.start()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)