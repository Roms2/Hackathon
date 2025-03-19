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

    # Filtres
    html.Div([
        html.Label("Filtrer par protocole :"),
        dcc.Dropdown(
            id="protocol-filter",
            options=[
                {"label": "Tous", "value": "all"},
                {"label": "TCP", "value": "TCP"},
                {"label": "UDP", "value": "UDP"},
                {"label": "ICMP", "value": "ICMP"}
            ],
            value="all",
            clearable=False,
            style={"width": "30%"}
        ),
        
        html.Label("Filtrer par IP Source :"),
        dcc.Dropdown(
            id="source-ip-filter",
            multi=True,
            placeholder="Sélectionnez une ou plusieurs IP...",
            style={"width": "30%"}
        ),

        html.Label("Filtrer par IP Destination :"),
        dcc.Dropdown(
            id="destination-ip-filter",
            multi=True,
            placeholder="Sélectionnez une ou plusieurs IP...",
            style={"width": "30%"}
        ),

        html.Label("Filtrer par Score d'Anomalie :"),
        dcc.RangeSlider(
            id="anomaly-score-filter",
            min=0, max=1, step=0.01,
            marks={0: "0", 0.5: "0.5", 1: "1"},
            value=[0, 1]
        ),
    ], style={"display": "flex", "flexWrap": "wrap", "gap": "20px"}),

    # Bouton pour charger les données
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

    # Graphiques supplémentaires
    dcc.Graph(id="anomaly-histogram"),
    dcc.Graph(id="protocol-pie-chart"),
    dcc.Graph(id="source-ip-bar-chart"),

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


# Callback pour mettre à jour les options des filtres IP en fonction des données récupérées
@app.callback(
    [Output("source-ip-filter", "options"),
     Output("destination-ip-filter", "options")],
    [Input("stored-data", "data")]
)
def update_ip_filters(stored_data):
    df = pd.DataFrame(stored_data)
    if df.empty:
        return [], []

    source_ips = [{"label": ip, "value": ip} for ip in df["source_ip"].unique()]
    destination_ips = [{"label": ip, "value": ip} for ip in df["destination_ip"].unique()]
    
    return source_ips, destination_ips


# Callback pour mettre à jour les graphiques et le tableau en fonction des filtres
@app.callback(
    [Output("network-traffic-graph", "figure"),
     Output("log-table", "data"),
     Output("anomaly-histogram", "figure"),
     Output("protocol-pie-chart", "figure"),
     Output("source-ip-bar-chart", "figure")],
    [Input("stored-data", "data"),
     Input("source-ip-filter", "value"),
     Input("destination-ip-filter", "value"),
     Input("anomaly-score-filter", "value")]
)
def update_visuals(stored_data, selected_source_ips, selected_destination_ips, anomaly_range):
    df = pd.DataFrame(stored_data)

    if df.empty:
        empty_fig = px.scatter(title="Aucune donnée disponible")
        return empty_fig, [], empty_fig, empty_fig, empty_fig

    # Filtrage des données
    df = df[(df["anomaly_score"] >= anomaly_range[0]) & (df["anomaly_score"] <= anomaly_range[1])]

    if selected_source_ips:
        df = df[df["source_ip"].isin(selected_source_ips)]
    
    if selected_destination_ips:
        df = df[df["destination_ip"].isin(selected_destination_ips)]

    # Graphique des connexions réseau avec anomalies
    traffic_fig = px.scatter(
        df,
        x="timestamp",
        y="anomaly_score",
        color="source_ip",
        title="Activité Réseau & Anomalies",
        labels={"timestamp": "Temps", "anomaly_score": "Score d'Anomalie"},
        size="anomaly_score",
        hover_data=["source_ip", "destination_ip", "port"]
    )

    # Histogramme des scores d'anomalie
    anomaly_histogram = px.histogram(
        df, x="anomaly_score", nbins=20,
        title="Distribution des Scores d'Anomalie",
        labels={"anomaly_score": "Score d'Anomalie"}
    )

    # Graphique circulaire des protocoles utilisés
    protocol_pie = px.pie(
        df, names="protocol",
        title="Répartition des Protocoles Réseau"
    )

    # Graphique en barres des connexions par IP source
    source_ip_bar = px.bar(
        df["source_ip"].value_counts().reset_index(),
        x="index", y="source_ip",
        title="Nombre de Connexions par IP Source",
        labels={"index": "IP Source", "source_ip": "Nombre de Connexions"}
    )

    return traffic_fig, df.to_dict("records"), anomaly_histogram, protocol_pie, source_ip_bar


# Lancement du serveur Dash
if __name__ == '__main__':
    app.run_server(host='0.0.0.0', port=8051, debug=True)
