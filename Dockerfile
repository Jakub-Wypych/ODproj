# Użyj oficjalnego obrazu Nginx
FROM nginx:alpine

# Skopiuj konfigurację Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Skopiuj certyfikaty SSL
COPY ssl/certs/nginx-selfsigned.crt /ssl/certs/nginx-selfsigned.crt
COPY ssl/private/nginx-selfsigned.key /ssl/private/nginx-selfsigned.key

# Utwórz folder dla aplikacji i jej statycznych plików
RUN mkdir -p /var/www/mojastrona

# Ustawienia dla Nginx (możesz zmienić, jeśli masz dodatkowe potrzeby)
CMD ["nginx", "-g", "daemon off;"]
