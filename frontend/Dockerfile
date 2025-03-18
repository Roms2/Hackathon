FROM python:3.9-slim

WORKDIR /app


COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8051

CMD ["python", "app.py", "--server.port=8051", "--server.address=127.0.0.1"]