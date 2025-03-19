import dash
from dash import dcc, html, dash_table
import plotly.express as px
import pandas as pd
import requests
from dash.dependencies import Input, Output, State

# URL de l'API Backend
API_URL = "http://backend:8000/get_data"

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

    # Bouton pour demander les données filtrées
    html.Button("🔄 Charger les Données", id="load-data-btn", n_clicks=0),

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

    # Stockage des données (évite de recharger plusieurs fois les mêmes données)
    dcc.Store(id="stored-data"),
])

# Fonction pour récupérer les données depuis le backend en fonction des filtres
def fetch_data(protocol):
    print("🔄 Récupération des données en cours...")  # Log début récupération

    try:
        params = {"protocol": protocol} if protocol != "all" else {}
        response = requests.get(API_URL, params=params)

        if response.status_code == 200:
            print("✅ Données chargées avec succès !")  # Log succès
            return pd.DataFrame(response.json())

    except Exception as e:
        print(f"❌ Erreur lors de la récupération des données : {e}")

    return pd.DataFrame()


@app.callback(
    Output("stored-data", "data"),
    [Input("load-data-btn", "n_clicks")],
    [State("protocol-filter", "value")]
)
def store_data(n_clicks, selected_protocol):
    if n_clicks > 0:
        return fetch_data(selected_protocol).to_dict("records")
    return []


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
        labels={"timestamprinp": "Temps", "anomaly_score": "Score d'Anomalie"},
        size="anomaly_score",
        hover_data=["source_ip", "destination_ip", "port"]
    )

    return fig, df.to_dict("records")


# Lancement du serveur Dash
if __name__ == '__main__':
    app.run_server(host='0.0.0.0', port=8051, debug=True)
