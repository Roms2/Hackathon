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
                processed_data = preprocess_data(df)  
                #Envoyer le DataFrame à process_file()

                # Traiter le fichier avec la fonction process_file() (retourne un dataframe ou une liste de tuples)
                if processed_data:
                    # Connexion à la base de données
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()

                    # Vérifier que processed_data est bien sous forme de liste de valeurs
                    if isinstance(processed_data, list):
                        cursor.execute("""
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
                        """, (
                            datetime.utcnow().isoformat(),  # Ajout du timestamp automatique
                            processed_data[1],  # duration
                            processed_data[2],  # src_bytes
                            processed_data[3],  # dst_bytes
                            int(processed_data[4] == "VRAI"),  # land
                            processed_data[5],  # wrong_fragment
                            processed_data[6],  # urgent
                            processed_data[7],  # hot
                            processed_data[8],  # num_failed_logins
                            int(processed_data[9] == "VRAI"),  # logged_in
                            processed_data[10],  # num_compromised
                            processed_data[11],  # root_shell
                            processed_data[12],  # su_attempted
                            processed_data[13],  # num_root
                            processed_data[14],  # num_file_creations
                            processed_data[15],  # num_shells
                            processed_data[16],  # num_access_files
                            processed_data[17],  # num_outbound_cmds
                            int(processed_data[18] == "VRAI"),  # is_host_login
                            int(processed_data[19] == "VRAI"),  # is_guest_login
                            processed_data[20],  # count
                            processed_data[21],  # srv_count
                            processed_data[22],  # serror_rate
                            processed_data[23],  # srv_serror_rate
                            processed_data[24],  # rerror_rate
                            processed_data[25],  # srv_rerror_rate
                            processed_data[26],  # same_srv_rate
                            processed_data[27],  # diff_srv_rate
                            processed_data[28],  # srv_diff_host_rate
                            processed_data[29],  # dst_host_count
                            processed_data[30],  # dst_host_srv_count
                            processed_data[31],  # dst_host_same_srv_rate
                            processed_data[32],  # dst_host_diff_srv_rate
                            processed_data[33],  # dst_host_same_src_port_rate
                            processed_data[34],  # dst_host_srv_diff_host_rate
                            processed_data[35],  # dst_host_serror_rate
                            processed_data[36],  # dst_host_srv_serror_rate
                            processed_data[37],  # dst_host_rerror_rate
                            processed_data[38],  # dst_host_srv_rerror_rate
                            int(processed_data[39] == "VRAI"),  # protocol_type_icmp
                            int(processed_data[40] == "VRAI"),  # protocol_type_tcp
                            int(processed_data[41] == "VRAI"),  # protocol_type_udp
                            int(processed_data[42] == "VRAI"),  # flag_OTH
                            int(processed_data[43] == "VRAI"),  # flag_REJ
                            int(processed_data[44] == "VRAI"),  # flag_RSTO
                            int(processed_data[45] == "VRAI"),  # flag_RSTOS0
                            int(processed_data[46] == "VRAI"),  # flag_RSTR
                            int(processed_data[47] == "VRAI"),  # flag_S0
                            int(processed_data[48] == "VRAI"),  # flag_S1
                            int(processed_data[49] == "VRAI"),  # flag_S2
                            int(processed_data[50] == "VRAI"),  # flag_S3
                            int(processed_data[51] == "VRAI"),  # flag_SF
                            int(processed_data[52] == "VRAI"),  # flag_SH
                            processed_data[53]  # label
                        ))

                    conn.commit()
                    conn.close()
                    print("✅ Données insérées en BDD")




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