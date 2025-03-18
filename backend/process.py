import numpy as np
import pandas as pd
import joblib

REFERENCE_COLUMNS_PATH = "reference_columns.pkl"
REFERENCE_COLUMNS_POST_PROCESSING_PATH = "reference_columns_post_processing.pkl"


def preprocess_data(df):
    """
    Prétraite les données brutes pour qu'elles correspondent aux attentes du modèle :
    - Applique One-Hot Encoding uniquement aux colonnes "protocol_type" et "flag"
    - Ajoute les colonnes manquantes (remplies avec des 0) via `concat()`
    - Supprime les colonnes en trop pour correspondre exactement aux 54 colonnes attendues
    - Convertit les booléens "VRAI"/"FAUX" en 1/0
    - Ajoute les colonnes absentes après traitement avec des valeurs 0
    - Retourne un DataFrame final avec les 54 colonnes attendues
    """

    # Charger la liste des colonnes attendues pour l'encodage
    reference_columns = joblib.load(REFERENCE_COLUMNS_PATH)

    # Vérifier que le DataFrame a bien le bon nombre de colonnes avant encodage
    expected_raw_columns = 42  # Modifier si le fichier brut a un autre nombre de colonnes
    if df.shape[1] != expected_raw_columns:
        print(f"⚠️ Erreur : {df.shape[1]} colonnes trouvées au lieu de {expected_raw_columns}. Fichier ignoré.")
        return None  # Retourne `None` pour éviter de traiter un mauvais fichier

    # Assigner les noms de colonnes à partir de reference_columns
    df.columns = reference_columns[:df.shape[1]]

    # Identifier les colonnes à encoder
    categorical_columns = ["protocol_type", "flag"]
    df_encoded = pd.get_dummies(df, columns=categorical_columns)

    # Convertir "VRAI"/"FAUX" en 1/0
    df_encoded = df_encoded.replace({"VRAI": 1, "FAUX": 0})

    # Charger les colonnes attendues après traitement
    reference_columns_post_processing = joblib.load(REFERENCE_COLUMNS_POST_PROCESSING_PATH)

    # Ajouter les colonnes manquantes avec des 0
    missing_cols = list(set(reference_columns_post_processing) - set(df_encoded.columns))
    if missing_cols:
        print(f"➕ Ajout de {len(missing_cols)} colonnes manquantes après traitement : {missing_cols}")
        missing_df = pd.DataFrame(0, index=df_encoded.index, columns=missing_cols)
        df_encoded = pd.concat([df_encoded, missing_df], axis=1)

    # Forcer le bon ordre des colonnes
    df_encoded = df_encoded[reference_columns_post_processing]

    # Vérification finale du nombre de colonnes
    if df_encoded.shape[1] != len(reference_columns_post_processing):
        print(f"❌ ERREUR : {df_encoded.shape[1]} colonnes générées, mais {len(reference_columns_post_processing)} attendues !")
        return None

    print(f"✅ Colonnes après correction : {df_encoded.shape[1]} colonnes (Attendu : {len(reference_columns_post_processing)})")

    return df_encoded