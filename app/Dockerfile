# Użyj obrazu Python jako bazy
FROM python:3.9-slim

# Zainstaluj wymagane pakiety do kompilacji uWSGI
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Ustaw katalog roboczy w kontenerze
WORKDIR /app

# Skopiuj pliki aplikacji do kontenera
COPY . /app

# Zainstaluj wymagania aplikacji
RUN pip install --no-cache-dir -r requirements.txt

# Upewnij się, że uWSGI jest zainstalowane
RUN pip install uwsgi

# Utwórz folder na socket uWSGI
RUN mkdir -p /tmp

# Ustawienia dla uWSGI przy użyciu pliku konfiguracyjnego
CMD ["uwsgi", "--ini", "app.ini"]

