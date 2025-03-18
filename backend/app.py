from fastapi import FastAPI, HTTPException
import sqlite3
import pandas as pd
import joblib
from datetime import datetime
import os
import time
import threading
from process import preprocess_data  # Fonction de prétraitement
import sys

# ------------------------ 1️⃣ 🚀 INITIALISATION VARIABLES ------------------------

DB_PATH = "/app/network_traffic.db"  # 🔹 Assurez-vous que ce chemin est correct !
MODEL_PATH = "model.pkl"
WATCHED_FOLDER = "/app/watched_folder"

# Charger le modèle ML
model = joblib.load(MODEL_PATH)

# ------------------------ 2️⃣ 🗄️ INITIALISATION BDD ------------------------

def init_db():
    """
    Initialise la base de données SQLite en créant la table `connections` si elle n’existe pas.
    """
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cursor = conn.cursor()

        # Création de la table avec 117 colonnes + timestamp
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
                service_IRC INTEGER,
                service_X11 INTEGER,
                service_Z39_50 INTEGER,
                service_auth INTEGER,
                service_bgp INTEGER,
                service_courier INTEGER,
                service_csnet_ns INTEGER,
                service_ctf INTEGER,
                service_daytime INTEGER,
                service_discard INTEGER,
                service_domain INTEGER,
                service_domain_u INTEGER,
                service_echo INTEGER,
                service_eco_i INTEGER,
                service_ecr_i INTEGER,
                service_efs INTEGER,
                service_exec INTEGER,
                service_finger INTEGER,
                service_ftp INTEGER,
                service_ftp_data INTEGER,
                service_gopher INTEGER,
                service_hostnames INTEGER,
                service_http INTEGER,
                service_http_443 INTEGER,
                service_imap4 INTEGER,
                service_iso_tsap INTEGER,
                service_klogin INTEGER,
                service_kshell INTEGER,
                service_ldap INTEGER,
                service_link INTEGER,
                service_login INTEGER,
                service_mtp INTEGER,
                service_name INTEGER,
                service_netbios_dgm INTEGER,
                service_netbios_ns INTEGER,
                service_netbios_ssn INTEGER,
                service_netstat INTEGER,
                service_nnsp INTEGER,
                service_nntp INTEGER,
                service_ntp_u INTEGER,
                service_other INTEGER,
                service_pm_dump INTEGER,
                service_pop_2 INTEGER,
                service_pop_3 INTEGER,
                service_printer INTEGER,
                service_private INTEGER,
                service_remote_job INTEGER,
                service_rje INTEGER,
                service_shell INTEGER,
                service_smtp INTEGER,
                service_sql_net INTEGER,
                service_ssh INTEGER,
                service_sunrpc INTEGER,
                service_supdup INTEGER,
                service_systat INTEGER,
                service_telnet INTEGER,
                service_tftp_u INTEGER,
                service_tim_i INTEGER,
                service_time INTEGER,
                service_urp_i INTEGER,
                service_uucp INTEGER,
                service_uucp_path INTEGER,
                service_vmnet INTEGER,
                service_whois INTEGER,
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
                flag_SH INTEGER
            )
        """)
        conn.commit()
        print("✅ Table 'connections' initialisée avec succès.", flush=True)
    except Exception as e:
        print(f"❌ Erreur lors de l'initialisation de la base de données : {e}",flush=True)
    finally:
        conn.close()

# Lancer l'initialisation au démarrage
init_db()

# ------------------------ 3️⃣ 👀 SURVEILLANCE TEMPS RÉEL ------------------------

def watch_and_process():
    """
    Surveille un dossier en temps réel et insère les données en BDD.
    """
    if not os.path.exists(WATCHED_FOLDER):
        os.makedirs(WATCHED_FOLDER)

    while True:
        try:
            files = [f for f in os.listdir(WATCHED_FOLDER) if os.path.isfile(os.path.join(WATCHED_FOLDER, f))]
            
            if files:
                latest_file = min(files, key=lambda f: os.path.getctime(os.path.join(WATCHED_FOLDER, f)))
                file_path = os.path.join(WATCHED_FOLDER, latest_file)
                
                print(f"📂 Nouvelle alerte détectée : {latest_file}", flush=True)

                df_raw = pd.read_csv(file_path, delimiter=",", header=None)
                print(f"🔍 {len(df_raw)} lignes trouvées", flush=True)

                df_processed = preprocess_data(df_raw)

                if df_processed.shape[1] != 117:
                    print(f"⚠️ Erreur après preprocessing : {df_processed.shape[1]} colonnes trouvées, 117 attendues.", flush=True)
                    os.remove(file_path)
                    continue
                
                df_processed.insert(0, "timestamp", datetime.utcnow().isoformat())

                conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                cursor = conn.cursor()
                print(f"📊 Vérification avant insertion :",flush=True)

                print(f"🔢 Colonnes du DataFrame traité : {df_processed.shape[1]}",flush=True)
                print(f"🔢 Nombre de valeurs par ligne : {len(df_processed.values.tolist()[0])}",flush=True)
                print(f"🧐 Colonnes du DataFrame après preprocessing: {df_processed.columns.tolist()}", flush=True)


                try:
                    cursor.executemany("""
                        INSERT INTO connections 
                        (timestamp, duration, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot, 
                        num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, 
                        num_file_creations, num_shells, num_access_files, num_outbound_cmds, is_host_login, 
                        is_guest_login, count, srv_count, serror_rate, srv_serror_rate, rerror_rate, 
                        srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count, 
                        dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, 
                        dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, 
                        dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate, 
                        protocol_type_icmp, protocol_type_tcp, protocol_type_udp, service_IRC, service_X11, 
                        service_Z39_50, service_auth, service_bgp, service_courier, service_csnet_ns, 
                        service_ctf, service_daytime, service_discard, service_domain, service_domain_u, 
                        service_echo, service_eco_i, service_ecr_i, service_efs, service_exec, service_finger, 
                        service_ftp, service_ftp_data, service_gopher, service_hostnames, service_http, 
                        service_http_443, service_imap4, service_iso_tsap, service_klogin, service_kshell, 
                        service_ldap, service_link, service_login, service_mtp, service_name, service_netbios_dgm, 
                        service_netbios_ns, service_netbios_ssn, service_netstat, service_nnsp, service_nntp, 
                        service_ntp_u, service_other, service_pm_dump, service_pop_2, service_pop_3, service_printer, 
                        service_private, service_remote_job, service_rje, service_shell, service_smtp, 
                        service_sql_net, service_ssh, service_sunrpc, service_supdup, service_systat, 
                        service_telnet,service_tftp_u, service_tim_i, service_time, service_urp_i, service_uucp, service_uucp_path, 
                        service_vmnet, service_whois, flag_OTH, flag_REJ, flag_RSTO, flag_RSTOS0, flag_RSTR, 
                        flag_S0, flag_S1, flag_S2, flag_S3, flag_SF, flag_SH) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? ,? , ?, ?, ?, ?)
                    """, df_processed.values.tolist())

                    conn.commit()
                    print(f"✅ {len(df_processed)} lignes insérées", flush=True)
                except Exception as e:
                    print(f"❌ Erreur lors de l'insertion SQL: {e}", flush=True)
                finally:
                    conn.close()

                os.remove(file_path)
                print(f"🗑️ Fichier supprimé : {latest_file}", flush=True)

            time.sleep(3)

        except Exception as e:
            print(f"⚠️ Erreur : {e}", flush=True)
            time.sleep(3)

# Délai avant lancement pour s'assurer que la BDD est prête
time.sleep(2)

# Lancer le thread de surveillance
thread = threading.Thread(target=watch_and_process, daemon=True)
thread.start()

# ------------------------ 4️⃣ 🚀 API FASTAPI ------------------------

app = FastAPI()

@app.get("/get_data")
def get_data():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM connections")
    count = cursor.fetchone()[0]
    conn.close()
    return {"total_rows": count}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
