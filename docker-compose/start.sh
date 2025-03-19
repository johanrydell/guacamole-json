echo "JSON_SECRET_KEY=$(openssl rand -hex 16)" > .env && docker-compose up -d
