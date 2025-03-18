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
    - Retourne un DataFrame final avec les 54 colonnes attendues (incluant "label")
    """

    # ✅ Charger les colonnes de référence et s'assurer qu'elles sont sous forme de liste
    reference_columns = list(joblib.load(REFERENCE_COLUMNS_PATH))  # Assurer que c'est bien une liste

    # ✅ Appliquer One-Hot Encoding
    df_encoded = pd.get_dummies(df)

    # ✅ Convertir "VRAI"/"FAUX" en 1/0 si nécessaire
    df_encoded = df_encoded.replace({"VRAI": 1, "FAUX": 0}).astype(int)

    # ✅ S'assurer que toutes les colonnes de référence sont présentes
    df_encoded = df_encoded.reindex(columns=reference_columns, fill_value=0)

    # ✅ Ajouter la colonne "label" s'il manque la dernière colonne
    if "label" not in df_encoded.columns:
        df_encoded["label"] = "unknown"  # Valeur par défaut
    
    print(f"🧐 Colonnes après encodage: {df_encoded.shape[1]} colonnes trouvées")
    print(f"👉 Colonnes présentes: {list(df_encoded.columns)}")


    return df_encoded
