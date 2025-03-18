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


EXPOSE 8000

CMD ["python", "app.py"]