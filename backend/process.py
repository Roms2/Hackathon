import numpy as np
import pandas as pd
import joblib

REFERENCE_COLUMNS_PATH = "reference_columns.pkl"

def preprocess_data(df):
    """
    Prétraite les données brutes pour qu'elles correspondent aux attentes du modèle :
    - Applique One-Hot Encoding avec un ensemble de colonnes fixes
    - Ajoute les colonnes manquantes (remplies avec des 0) via `concat()`
    - Convertit les booléens "VRAI"/"FAUX" en 1/0
    - Retourne un DataFrame final avec les 54 colonnes attendues
    """
    # Charger la liste des colonnes attendues pour l'encodage
    reference_columns = joblib.load(REFERENCE_COLUMNS_PATH)

    # Appliquer One-Hot Encoding
    df_encoded = pd.get_dummies(df)

    # Convertir "VRAI"/"FAUX" en 1/0 si nécessaire
    df_encoded = df_encoded.replace({"VRAI": 1, "FAUX": 0})

    # Identifier les colonnes manquantes
    missing_cols = list(set(reference_columns) - set(df_encoded.columns))
    
    # Ajouter les colonnes manquantes en une seule opération pour éviter la fragmentation
    if missing_cols:
        print(f"➕ Ajout de {len(missing_cols)} colonnes manquantes : {missing_cols}")
        missing_df = pd.DataFrame(0, index=df_encoded.index, columns=missing_cols)
        df_encoded = pd.concat([df_encoded, missing_df], axis=1)

    # Réorganiser les colonnes dans l'ordre correct
    df_encoded = df_encoded[reference_columns]

    # Ajouter une colonne label si elle n'existe pas
    if 'label' not in df_encoded.columns:
        df_encoded['label'] = 'default'

    print(f"✅ Colonnes après correction : {df_encoded.shape[1]} colonnes")

    return df_encoded
