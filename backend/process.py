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
    - Retourne un DataFrame final avec les 54 colonnes attendues
    """
    # Charger la liste des colonnes attendues pour l'encodage
    reference_columns = joblib.load(REFERENCE_COLUMNS_PATH)

    # Appliquer One-Hot Encoding
    df_encoded = pd.get_dummies(df)
    
    # Convertir "VRAI"/"FAUX" en 1/0 si nécessaire
    df_encoded = df_encoded.replace({"VRAI": 1, "FAUX": 0})
    
    # Vérifier les colonnes après encodage
    common_cols = set(df_encoded.columns) & set(reference_columns)
    missing_cols = set(reference_columns) - set(df_encoded.columns)
    extra_cols = set(df_encoded.columns) - set(reference_columns)
    
    # Supprimer les colonnes en trop
    if extra_cols:
        print(f"⚠️ Suppression de {len(extra_cols)} colonnes en trop : {extra_cols}")
        df_encoded = df_encoded.drop(columns=extra_cols)
    
    # Ajouter les colonnes manquantes avec des 0
    if missing_cols:
        print(f"➕ Ajout de {len(missing_cols)} colonnes manquantes : {missing_cols}")
        for col in missing_cols:
            df_encoded[col] = 0
    
    # Réorganiser les colonnes dans l'ordre correct
    df_encoded = df_encoded[reference_columns]
    
    # Ajouter une colonne label si elle n'existe pas
    if 'label' not in df_encoded.columns:
        df_encoded['label'] = 'default'
    
    print(f"✅ Colonnes après correction : {df_encoded.shape[1]} colonnes")
    
    return df_encoded
