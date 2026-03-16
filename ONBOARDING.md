# ONBOARDING — kradra-backend

Короткая шпаргалка для локального запуска, test DB и integration tests.

## 1. Клон проекта

```bash
git clone git@github.com:mainfish/kradra-backend.git
cd kradra-backend
```

## 2. Локальный `.env`

`.env` не хранится в git.

```bash
cp .env.example .env
```

Проверь, что в `.env` есть обе строки:

```env
DATABASE_URL=postgres://kradra:kradra_local_password@127.0.0.1:5432/kradra
DATABASE_URL_TEST=postgres://kradra:kradra_local_password@127.0.0.1:5432/kradra_test
```

- `DATABASE_URL` — dev база
- `DATABASE_URL_TEST` — отдельная база для integration tests

## 3. Поднять PostgreSQL

```bash
docker compose up -d
docker compose ps
docker exec -it kradra-postgres psql -U kradra -d kradra -c "SELECT 1;"
```

## 4. Создать test DB

Если `kradra_test` ещё не существует:

```bash
docker exec -it kradra-postgres psql -U kradra -d postgres -c "CREATE DATABASE kradra_test OWNER kradra;"
```

Проверить список баз:

```bash
docker exec -it kradra-postgres psql -U kradra -d postgres -c "\l"
```

## 5. Прогнать миграции

### Dev DB

```bash
DATABASE_URL=postgres://kradra:kradra_local_password@127.0.0.1:5432/kradra cargo sqlx migrate run
```

### Test DB

```bash
DATABASE_URL=postgres://kradra:kradra_local_password@127.0.0.1:5432/kradra_test cargo sqlx migrate run
```

Проверка таблиц:

```bash
docker exec -it kradra-postgres psql -U kradra -d kradra -c "\dt"
docker exec -it kradra-postgres psql -U kradra -d kradra_test -c "\dt"
```

## 6. Сборка и запуск API

```bash
cargo build
cargo run -p kradra-api
```

## 7. Быстрые проверки API

В другом терминале:

```bash
curl -i http://127.0.0.1:20443/health
curl -i http://127.0.0.1:20443/health/readiness
curl -i http://127.0.0.1:20443/api/ping
curl -i http://127.0.0.1:20443/nope
```

## 8. Integration tests

### Admin flow

```bash
cargo test --test admin_flow
```

### Auth flow

```bash
cargo test --test auth_flow
```

Важно:
- integration tests используют `DATABASE_URL_TEST`
- test harness очищает test DB перед запуском тестового приложения
- dev DB и test DB должны быть разными

## 9. Полезные команды для просмотра данных

### Users в dev DB

```bash
docker exec -it kradra-postgres psql -U kradra -d kradra -c \
"select id, username, role, is_active, created_at from users order by created_at desc;"
```

### Users в test DB

```bash
docker exec -it kradra-postgres psql -U kradra -d kradra_test -c \
"select id, username, role, is_active, created_at from users order by created_at desc;"
```

## 10. Частые проблемы

### `PoolTimedOut`
- Postgres не поднят
- неправильный `DATABASE_URL` или `DATABASE_URL_TEST`

### `DATABASE_URL_TEST is not set`
- integration tests требуют отдельную test DB
- проверь `.env`

### `password authentication failed`
- проверь пароль в `.env`
- локально используется `kradra_local_password`

### Тесты пишут мусор в dev DB
- это значит, что test DB настроена неправильно
- integration tests должны ходить только в `kradra_test`

### Полный сброс локального Postgres (удалит данные)

```bash
docker rm -f kradra-postgres 2>/dev/null
docker volume rm kradra_postgres_data 2>/dev/null
docker compose up -d
```

Потом снова:
- создать `kradra_test`
- прогнать миграции в `kradra`
- прогнать миграции в `kradra_test`
