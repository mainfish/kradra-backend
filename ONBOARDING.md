# ONBOARDING — kradra-backend (шпаргалка)

## 1) Клон
```bash
git clone git@github.com:mainfish/kradra-backend.git
cd kradra-backend
```

## 2) Локальный `.env` (обязательно)
`.env` не хранится в git.
```bash
cp .env.example .env
```

## 3) Поднять PostgreSQL (Docker)
```bash
docker compose up -d
docker compose ps
docker exec -it kradra-postgres psql -U kradra -d kradra -c "SELECT 1;"
```

## 4) Миграции
```bash
sqlx --version
sqlx migrate run
docker exec -it kradra-postgres psql -U kradra -d kradra -c "\dt"
```

## 5) Сборка и запуск API
```bash
cargo build
cargo run -p kradra-api
```

## 6) Быстрые проверки API
(в другом терминале)
```bash
curl -i http://127.0.0.1:20443/health
curl -i http://127.0.0.1:20443/health/readiness
curl -i http://127.0.0.1:20443/api/ping
curl -i http://127.0.0.1:20443/nope
```

## Частые проблемы
- **`PoolTimedOut`**: Postgres не поднят или неправильный `DATABASE_URL` в `.env`.
- **Порт 5432 занят**:
  ```bash
  lsof -nP -iTCP:5432 | grep LISTEN
  ```
- **Полный сброс БД (удалит данные!)**
  ```bash
  docker rm -f kradra-postgres 2>/dev/null
  docker volume rm kradra_postgres_data 2>/dev/null
  ```
  Потом снова: `docker compose up -d` → `sqlx migrate run`.
