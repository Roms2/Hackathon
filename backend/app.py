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
import sys



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
            src_bytes INTEGER,
            dst_bytes INTEGER,
            land INTEGER,
            wrong_fragment INTEGER,
            urgent INTEGER,
            hot INTEGER,
            num_failed_logins INTEGER,
            logged_in INTEGER,
            num_compromised INTEGER,
            root_shell INTEGER,
            su_attempted INTEGER,
            num_root INTEGER,
            num_file_creations INTEGER,
            num_shells INTEGER,
            num_access_files INTEGER,
            num_outbound_cmds INTEGER,
            is_host_login INTEGER,
            is_guest_login INTEGER,
            count INTEGER,
            srv_count INTEGER,
            serror_rate REAL,
            srv_serror_rate REAL,
            rerror_rate REAL,
            srv_rerror_rate REAL,
            same_srv_rate REAL,
            diff_srv_rate REAL,
            srv_diff_host_rate REAL,
            dst_host_count INTEGER,
            dst_host_srv_count INTEGER,
            dst_host_same_srv_rate REAL,
            dst_host_diff_srv_rate REAL,
            dst_host_same_src_port_rate REAL,
            dst_host_srv_diff_host_rate REAL,
            dst_host_serror_rate REAL,
            dst_host_srv_serror_rate REAL,
            dst_host_rerror_rate REAL,
            dst_host_srv_rerror_rate REAL,
            protocol_type_icmp INTEGER,
            protocol_type_tcp INTEGER,
            protocol_type_udp INTEGER,
            flag_OTH INTEGER,
            flag_REJ INTEGER,
            flag_RSTO INTEGER,
            flag_RSTOS0 INTEGER,
            flag_RSTR INTEGER,
            flag_S0 INTEGER,
            flag_S1 INTEGER,
            flag_S2 INTEGER,
            flag_S3 INTEGER,
            flag_SF INTEGER,
            flag_SH INTEGER,
            label TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()  # Initialisation au démarrage


# ------------------------ 3️⃣ 👀 SURVEILLANCE TEMPS RÉEL ------------------------



WATCHED_FOLDER = "/app/watched_folder"
DB_PATH = "/app/network_traffic.db"

def watch_and_process():
    """
    Surveille un dossier en temps réel, détecte le fichier le plus récent,
    lit toutes les lignes du fichier en une seule fois, les envoie à preprocess_data() en batch,
    puis stocke les données traitées en BDD dans une seule transaction.
    """

    if not os.path.exists(WATCHED_FOLDER):
        os.makedirs(WATCHED_FOLDER)

    while True:
        try:
            # Liste tous les fichiers du dossier
            files = [f for f in os.listdir(WATCHED_FOLDER) if os.path.isfile(os.path.join(WATCHED_FOLDER, f))]
            
            if files:
                # Trouver le fichier le plus récent
                latest_file = min(files, key=lambda f: os.path.getctime(os.path.join(WATCHED_FOLDER, f)))
                file_path = os.path.join(WATCHED_FOLDER, latest_file)
                
                
                print(f"📂 Nouvelle alerte détectée : {latest_file}", flush=True)  # Forcer l'affichage du log immédiatement


                # Charger tout le fichier d'un coup dans un DataFrame
                df_raw = pd.read_csv(file_path, delimiter=",", header=None)  # Adapter le délimiteur si nécessaire
                print(f"🔍 {len(df_raw)} lignes trouvées dans le fichier", flush=True)

                # Vérifier que le fichier a bien 43 colonnes
                if df_raw.shape[1] < 42:  
                    print(f"⚠️ Fichier ignoré, nombre de colonnes incorrect ({df_raw.shape[1]} colonnes trouvées, 43 attendues).")
                    os.remove(file_path)  # Supprimer le fichier invalide
                    continue
                print(f"📝 Données brutes avant preprocessing: {df_raw.shape}")
                print(df_raw.head())  # Affiche les 5 premières lignes

                # Envoyer toutes les lignes à preprocess_data() en une seule fois
                df_processed = preprocess_data(df_raw)

                # Vérifier le nombre de colonnes après preprocessing
                expected_columns = 54
                if df_processed.shape[1] != expected_columns:
                    print(f"⚠️ Erreur après preprocessing : {df_processed.shape[1]} colonnes trouvées, {expected_columns} attendues.")
                    os.remove(file_path)
                    continue
                
                # Ajouter une colonne "timestamp" pour chaque ligne
                df_processed.insert(0, "timestamp", datetime.utcnow().isoformat())

                # Connexion à la base de données (une seule connexion pour toutes les lignes)
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()

                # Insérer toutes les lignes d'un coup avec `executemany()`
                try:
                    cursor.executemany("""
                        INSERT INTO connections 
                        (timestamp, duration, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot, num_failed_logins, 
                        logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, 
                        num_access_files, num_outbound_cmds, is_host_login, is_guest_login, count, srv_count, serror_rate, 
                        srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate, 
                        dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, 
                        dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate, 
                        protocol_type_icmp, protocol_type_tcp, protocol_type_udp, flag_OTH, flag_REJ, flag_RSTO, flag_RSTOS0, 
                        flag_RSTR, flag_S0, flag_S1, flag_S2, flag_S3, flag_SF, flag_SH, label) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, df_processed.values.tolist())

                    # Valider la transaction
                    conn.commit()
                    print(f"✅ {len(df_processed)} lignes insérées en BDD")

                    # Vérifier combien de lignes sont en base après insertion
                    cursor.execute("SELECT COUNT(*) FROM connections")
                    count = cursor.fetchone()[0]
                    print(f"📊 Nombre total d'entrées en BDD après insertion: {count}")

                except Exception as e:
                    print(f"❌ Erreur lors de l'insertion SQL: {e}")
                
                finally:
                    conn.close()  # Toujours fermer la connexion à la BDD

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


import threading

if __name__ == "__main__":
    thread = threading.Thread(target=watch_and_process, daemon=True)
    thread.start()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
