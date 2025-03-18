import numpy as np
import pandas as pd
import joblib

REFERENCE_COLUMNS_PATH = "reference_columns.pkl"

def preprocess_data(df):
    """
    Prétraite les données brutes pour qu'elles correspondent aux attentes du modèle :
    - Applique One-Hot Encoding avec un ensemble de colonnes fixes
    - Ajoute les colonnes manquantes (remplies avec des 0) via `concat()`
    - Supprime les colonnes en trop pour correspondre exactement aux 54 colonnes attendues
    - Convertit les booléens "VRAI"/"FAUX" en 1/0
    - Retourne un DataFrame final avec les 54 colonnes attendues
    """

    # Charger la liste des colonnes attendues pour l'encodage
    reference_columns = joblib.load(REFERENCE_COLUMNS_PATH)

    # Vérifier que le DataFrame a bien le bon nombre de colonnes avant encodage
    expected_raw_columns = 42  # Modifier si le fichier brut a un autre nombre de colonnes
    if df.shape[1] != expected_raw_columns:
        print(f"⚠️ Erreur : {df.shape[1]} colonnes trouvées au lieu de {expected_raw_columns}. Fichier ignoré.")
        return None  # Retourne `None` pour éviter de traiter un mauvais fichier

    # Ajout temporaire d'un header pour éviter les erreurs avec `get_dummies`
    df.columns = [f"col_{i}" for i in range(df.shape[1])]

    # Appliquer One-Hot Encoding
    df_encoded = pd.get_dummies(df)

    # Convertir "VRAI"/"FAUX" en 1/0
    df_encoded = df_encoded.replace({"VRAI": 1, "FAUX": 0})

    # Vérifier les colonnes après encodage
    missing_cols = list(set(reference_columns) - set(df_encoded.columns))
    extra_cols = list(set(df_encoded.columns) - set(reference_columns))

    # **Supprimer les colonnes en trop**
    if extra_cols:
        print(f"⚠️ Suppression de {len(extra_cols)} colonnes en trop : {extra_cols}")
        df_encoded = df_encoded.drop(columns=extra_cols)

    # **Ajouter les colonnes manquantes avec des 0 via `concat()` pour éviter la fragmentation**
    if missing_cols:
        print(f"➕ Ajout de {len(missing_cols)} colonnes manquantes : {missing_cols}")
        missing_df = pd.DataFrame(0, index=df_encoded.index, columns=missing_cols)
        df_encoded = pd.concat([df_encoded, missing_df], axis=1)

    # **Forcer le bon ordre des colonnes**
    df_encoded = df_encoded[reference_columns]

    # Vérification finale du nombre de colonnes
    if df_encoded.shape[1] != len(reference_columns):
        print(f"❌ ERREUR : {df_encoded.shape[1]} colonnes générées, mais {len(reference_columns)} attendues !")
        return None

    print(f"✅ Colonnes après correction : {df_encoded.shape[1]} colonnes (Attendu : {len(reference_columns)})")

    return df_encoded


