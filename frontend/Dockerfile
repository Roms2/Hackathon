# Utilisez une image de base appropriée
FROM python:3.9-slim

# Définissez le répertoire de travail
WORKDIR /app

# Copiez le fichier requirements.txt dans le répertoire de travail
COPY requirements.txt .

# Installez les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copiez le reste de votre application
COPY . .

# Commande pour exécuter votre application
CMD ["python", "app.py"]
