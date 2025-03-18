import numpy as np
import pandas as pd
import joblib

REFERENCE_COLUMNS_PATH = "reference_columns.pkl"

def preprocess_data(df):
    """
    Prétraite les données brutes pour qu'elles correspondent aux attentes du modèle :
    - Applique One-Hot Encoding avec un ensemble de colonnes fixes
    - Ajoute les colonnes manquantes (remplies avec des 0)
    - Convertit les booléens "VRAI"/"FAUX" en 1/0
    - Retourne un DataFrame final avec les 53 colonnes attendues
    """

    # Charger la liste des colonnes attendues pour l'encodage
    reference_columns = joblib.load(REFERENCE_COLUMNS_PATH)

    # 🔹 Appliquer One-Hot Encoding
    df_encoded = pd.get_dummies(df)

    # 🔹 Convertir "VRAI"/"FAUX" en 1/0 si nécessaire
    df_encoded = df_encoded.replace({"VRAI": 1, "FAUX": 0})

    # 🔹 Ajouter les colonnes manquantes (pour éviter les erreurs de dimension)
    missing_cols = set(reference_columns) - set(df_encoded.columns)
    df_missing = pd.DataFrame(0, index=df_encoded.index, columns=missing_cols)

    # 🔹 Concaténer le DataFrame encodé avec les colonnes manquantes
    df_encoded = pd.concat([df_encoded, df_missing], axis=1)
    if 'label' not in df_encoded.columns:
        df_encoded['label'] = 'défault'

    # 🔹 Réorganiser les colonnes dans le bon ordre
    # S'assurer que les colonnes de référence sont une liste triée
    reference_columns = list(reference_columns)  # Conversion en liste si c'est un set

    # Réorganiser les colonnes dans l'ordre de référence
    df_encoded = df_encoded[reference_columns]
    df_encoded["label"] = "labels"


    return df_encoded

