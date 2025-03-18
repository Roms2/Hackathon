import dash
from dash import dcc, html, dash_table
import plotly.express as px
import pandas as pd
import random
import datetime
from dash.dependencies import Input, Output, State

# Initialisation de l'application Dash
app = dash.Dash(__name__)

# 🟢 **Données brutes simulées (remplace temporairement l'API)**
def generate_fake_data():
    now = datetime.datetime.now()
    data = []
    for _ in range(100):  # Générer 100 connexions réseau fictives
        data.append({
            "timestamp": (now - datetime.timedelta(seconds=random.randint(0, 3600))).isoformat(),
            "source_ip": f"192.168.1.{random.randint(1, 255)}",
            "destination_ip": f"10.0.0.{random.randint(1, 255)}",
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "port": random.choice([80, 443, 22, 21, 53]),
            "anomaly_score": round(random.uniform(0, 1), 2)  # Score d'anomalie simulé
        })
    return pd.DataFrame(data)

# Layout de l'application
app.layout = html.Div([
    html.H1("📡 Surveillance du Réseau & Détection d’Anomalies (Données Simulées)"),

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

    # Bouton pour charger les données locales
    html.Button("🔄 Charger les Données Simulées", id="load-data-btn", n_clicks=0),

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

    # Stockage des données simulées pour éviter de tout recalculer à chaque filtre
    dcc.Store(id="stored-data"),
])

# Callback pour stocker les données simulées
@app.callback(
    Output("stored-data", "data"),
    [Input("load-data-btn", "n_clicks")]
)
def store_data(n_clicks):
    if n_clicks > 0:
        df = generate_fake_data()
        return df.to_dict("records")
    return []

# Callback pour mettre à jour le graphique et le tableau
@app.callback(
    [Output("network-traffic-graph", "figure"),
     Output("log-table", "data")],
    [Input("stored-data", "data"),
     Input("protocol-filter", "value")]
)
def update_visuals(stored_data, selected_protocol):
    df = pd.DataFrame(stored_data)

    if df.empty:
        return px.scatter(title="Aucune donnée disponible"), []

    # Filtrer les données en fonction du protocole sélectionné
    if selected_protocol != "all":
        df = df[df["protocol"] == selected_protocol]

    # Graphique des connexions réseau avec anomalies
    fig = px.scatter(
        df,
        x="timestamp",
        y="anomaly_score",
        color="source_ip",
        title="Activité Réseau & Anomalies (Données Simulées)",
        labels={"timestamp": "Temps", "anomaly_score": "Score d'Anomalie"},
        size="anomaly_score",
        hover_data=["source_ip", "destination_ip", "port"]
    )

    return fig, df.to_dict("records")

# Lancement du serveur Dash
if __name__ == '__main__':
    app.run_server(host='0.0.0.0', port=8051, debug=True)
