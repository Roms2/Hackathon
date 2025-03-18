# Utilisez une image de base Python
FROM python:3.9-slim

# Définissez le répertoire de travail
WORKDIR /app

# Copiez le fichier requirements.txt dans le répertoire de travail
COPY requirements.txt .

# Installez les dépendances
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copiez le reste de votre application
COPY . .

# Exposez le port sur lequel votre application s'exécute
EXPOSE 8051

# Commande pour exécuter votre application
CMD ["python", "app.py", "--server.port=8051", "--server.address=127.0.0.1"]
