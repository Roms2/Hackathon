import dash
from dash import dcc, html, dash_table
import plotly.express as px
import pandas as pd
import requests
import random
import time
from dash.dependencies import Input, Output, State

# URL de l'API Backend pour récupérer des données et faire des prédictions
API_URL = "http://127.0.0.1:8000/api/get_data"
PREDICT_API_URL = "http://127.0.0.1:8000/api/predict"  # Endpoint fictif pour les prédictions

# Initialisation de l'application Dash
app = dash.Dash(__name__)

# Layout de l'application
app.layout = html.Div([
    html.H1("📡 Surveillance du Réseau & Détection d’Anomalies"),

    # Sélecteur de protocole (Filtre)
    dcc.Dropdown(
        id="protocol-filter",
        options=[{"label": "Tous", "value": "all"},
                 {"label": "TCP", "value": "TCP"},
                 {"label": "UDP", "value": "UDP"},
                 {"label": "ICMP", "value": "ICMP"}],
        value="all",
        clearable=False,
        style={"width": "50%"}
    ),

    # Boutons pour charger les données et simuler en temps réel
    html.Div([
        html.Button("🔄 Charger les Données", id="load-data-btn", n_clicks=0),
        html.Button("⚡ Simuler Temps Réel", id="simulate-btn", n_clicks=0, style={"margin-left": "10px"})
    ]),

    # Graphique des connexions réseau
    dcc.Graph(id="network-traffic-graph"),

    # Tableau des logs des connexions
    dash_table.DataTable(
        id="log-table",
        columns=[
            {"name": "Timestamp", "id": "timestamp"},
            {"name": "IP Source", "id": "source_ip"},
            {"name": "IP Destination", "id": "destination_ip"},
            {"name": "Protocole", "id": "protocol"},
            {"name": "Port", "id": "port"},
            {"name": "Score Anomalie", "id": "anomaly_score"}
        ],
        page_size=10,
        style_table={'overflowX': 'auto'}
    ),

    # Stockage des données
    dcc.Store(id="stored-data"),
])

# Fonction pour récupérer les données depuis le backend en fonction des filtres
def fetch_data(protocol):
    try:
        params = {"protocol": protocol} if protocol != "all" else {}
        response = requests.get(API_URL, params=params)
        if response.status_code == 200:
            return pd.DataFrame(response.json())
    except Exception as e:
        print(f"Erreur API : {e}")
    return pd.DataFrame()

# Fonction pour générer de fausses données
def generate_fake_data():
    protocols = ["TCP", "UDP", "ICMP"]
    return {
        "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": f"192.168.1.{random.randint(1, 255)}",
        "destination_ip": f"10.0.0.{random.randint(1, 255)}",
        "protocol": random.choice(protocols),
        "port": random.randint(1000, 65535)
    }

# Fonction pour obtenir une vraie prédiction du backend
def get_prediction(fake_data):
    try:
        response = requests.post(PREDICT_API_URL, json=fake_data)
        if response.status_code == 200:
            return response.json().get("anomaly_score", random.uniform(0, 1))
    except Exception as e:
        print(f"Erreur API : {e}")
    return random.uniform(0, 1)  # Valeur aléatoire en cas d'échec

# Callback pour charger les données filtrées depuis l'API
@app.callback(
    Output("stored-data", "data"),
    [Input("load-data-btn", "n_clicks")],
    [State("protocol-filter", "value")]
)
def store_data(n_clicks, selected_protocol):
    if n_clicks > 0:
        df = fetch_data(selected_protocol)
        return df.to_dict("records")
    return []

# Callback pour simuler des données en temps réel
@app.callback(
    Output("stored-data", "data"),
    [Input("simulate-btn", "n_clicks")],
    [State("stored-data", "data")]
)
def simulate_real_time(n_clicks, stored_data):
    if n_clicks > 0:
        stored_data = stored_data or []
        
        # Générer et envoyer plusieurs fausses données pour simuler un flux temps réel
        for _ in range(5):  # 5 itérations pour simuler du "temps réel"
            fake_data = generate_fake_data()
            fake_data["anomaly_score"] = get_prediction(fake_data)  # Ajouter le score réel
            stored_data.append(fake_data)
            time.sleep(1)  # Pause pour simuler l'arrivée progressive des données
        
        return stored_data
    return stored_data

# Callback pour mettre à jour le graphique et le tableau
@app.callback(
    [Output("network-traffic-graph", "figure"),
     Output("log-table", "data")],
    [Input("stored-data", "data")]
)
def update_visuals(stored_data):
    df = pd.DataFrame(stored_data)

    if df.empty:
        return px.scatter(title="Aucune donnée disponible"), []

    # Graphique des connexions réseau avec anomalies
    fig = px.scatter(
        df,
        x="timestamp",
        y="anomaly_score",
        color="source_ip",
        title="Activité Réseau & Anomalies",
        labels={"timestamp": "Temps", "anomaly_score": "Score d'Anomalie"},
        size="anomaly_score",
        hover_data=["source_ip", "destination_ip", "port"]
    )

    return fig, df.to_dict("records")

# Lancement du serveur Dash
if __name__ == '__main__':
    app.run_server(host='0.0.0.0', port=8051, debug=True)