import numpy as np
import pandas as pd
import joblib

def preprocess_data(df, scaler_path="scaler.pkl", reference_columns_path="reference_columns.pkl"):
    """
    Effectue le prétraitement des données pour la prédiction :
    - Applique One-Hot Encoding avec des colonnes fixes (celles de l'entraînement)
    - Charge le scaler pré-enregistré et normalise les données

    :param df: DataFrame brut (sans label)
    :param scaler_path: Chemin du fichier du scaler enregistré
    :param reference_columns_path: Chemin du fichier des colonnes utilisées pour One-Hot Encoding
    :return: DataFrame prétraité
    """

    # Charger les colonnes de référence pour One-Hot Encoding
    reference_columns = joblib.load(reference_columns_path)

    # Appliquer One-Hot Encoding
    df_encoded = pd.get_dummies(df)

    # S'assurer que toutes les colonnes de référence sont présentes
    for col in reference_columns:
        if col not in df_encoded.columns:
            df_encoded[col] = 0  # Ajouter la colonne manquante avec des 0

    # Réorganiser les colonnes dans le même ordre que lors de l'entraînement
    df_encoded = df_encoded[reference_columns]

    # Charger le scaler pré-enregistré
    scaler = joblib.load(scaler_path)
    df_scaled = scaler.transform(df_encoded)

    # Retourner un DataFrame normalisé
    return pd.DataFrame(df_scaled, columns=reference_columns)