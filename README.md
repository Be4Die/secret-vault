# 🔐 Secret Vault

**Минималистичный, безопасный менеджер секретов и паролей**

[![CI](https://github.com/Be4Die/secret-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/Be4Die/secret-vault/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57?style=flat&logo=sqlite&logoColor=white)](https://www.sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-white?style=flat)](LICENSE)

<br/>

<img src="https://img.shields.io/badge/AES--256--GCM-Encryption-black?style=for-the-badge" alt="AES-256-GCM"/>
<img src="https://img.shields.io/badge/bcrypt-Hashing-black?style=for-the-badge" alt="bcrypt"/>
<img src="https://img.shields.io/badge/Zero-CGO-black?style=for-the-badge" alt="Zero CGO"/>

</div>

---

## ✨ Возможности

- 🔑 **Управление учётными данными** — безопасное хранение логинов, паролей и заметок
- 🎟️ **Токены и API-ключи** — отдельное хранилище для токенов доступа
- 🔒 **AES-256-GCM шифрование** — все секреты зашифрованы на стороне сервера
- 🔐 **bcrypt хеширование** — пароли пользователей никогда не хранятся в открытом виде
- 🎲 **Генератор паролей** — настраиваемая генерация криптостойких паролей
- 🔍 **Fuzzy-поиск** — мгновенный поиск по всем секретам
- 📋 **Аудит-лог** — отслеживание всех действий пользователей
- 🌙 **Dark UI** — монохромный glassmorphism-дизайн в стиле Apple

## 🏗️ Архитектура

Проект построен на принципах **Clean Architecture** Роберта Мартина с жёстким правилом направления зависимостей:

```
infrastructure → adapter → usecase → entity
   (внешний)                         (ядро)
```

```
secret-vault/
├── cmd/server/              # Точка входа
├── internal/
│   ├── entity/              # Бизнес-сущности и правила
│   ├── usecase/             # Бизнес-логика и порты (интерфейсы)
│   ├── adapter/
│   │   ├── handler/         # HTTP-хендлеры
│   │   ├── repository/      # SQLite-реализации репозиториев
│   │   └── middleware/      # Auth, rate limiting, method override
│   ├── infrastructure/
│   │   ├── config/          # Конфигурация через env
│   │   ├── crypto/          # AES-256-GCM, bcrypt, key derivation
│   │   ├── database/        # Подключение SQLite
│   │   ├── router/          # Маршрутизация (chi)
│   │   ├── search/          # Fuzzy-поиск
│   │   └── session/         # Управление сессиями
│   └── integration/         # Интеграционные тесты
├── templates/               # Templ-шаблоны (layouts, pages, components)
├── migrations/              # SQL-схема
└── static/                  # CSS, JS (htmx, Tailwind)
```

## 🛠️ Стек технологий

| Компонент       | Технология                                         |
|-----------------|-----------------------------------------------------|
| **Язык**        | Go 1.25+                                           |
| **HTTP-роутер** | [chi/v5](https://github.com/go-chi/chi)            |
| **База данных** | SQLite (через [modernc.org/sqlite](https://modernc.org/sqlite) — pure Go, zero CGO) |
| **Шаблонизатор**| [templ](https://templ.guide)                       |
| **Стили**       | Tailwind CSS                                        |
| **Интерактивность** | [htmx](https://htmx.org)                      |
| **Конфигурация**| [cleanenv](https://github.com/ilyakaznacheev/cleanenv) |
| **Логирование** | slog (stdlib)                                       |

## 🚀 Быстрый старт

### Требования

- Go 1.25+
- [templ CLI](https://templ.guide/quick-start/installation)

### Локальный запуск

```bash
# Клонировать репозиторий
git clone https://github.com/Be4Die/secret-vault.git
cd secret-vault

# Установить зависимости
make setup

# Создать файл окружения
cp .env.example .env
# Отредактировать .env — обязательно задать MASTER_KEY

# Запустить
make dev
```

Приложение доступно на `http://localhost:8080`

### Docker

```bash
# Создать .env файл
cp .env.example .env

# Запустить
make docker-up

# Остановить и удалить данные
make docker-down
```

## ⚙️ Конфигурация


| Переменная       | Описание                        | Обязательная |
|------------------|---------------------------------|:------------:|
| `MASTER_KEY`     | Мастер-ключ шифрования секретов | ✅           |
| `HTTP_PORT`      | Порт HTTP-сервера               | —            |
| `DATABASE_PATH`  | Путь к файлу SQLite             | —            |
| `SESSION_SECRET` | Секрет для подписи сессий       | ✅           |

## 🧪 Тестирование

```bash
# Unit-тесты
make test

# Интеграционные тесты
make test-integration

# Все тесты
make test-all

# Покрытие
make test-coverage

# Race detector
make test-race
```

## 🔒 Безопасность

| Аспект              | Реализация                          |
|---------------------|--------------------------------------|
| Хеширование паролей | bcrypt (cost 12+)                   |
| Шифрование секретов | AES-256-GCM                         |
| Мастер-ключ         | Переменная окружения, не в коде      |
| Сессии              | Secure, HttpOnly, SameSite cookies  |
| Rate limiting       | На эндпоинтах аутентификации        |
| Аудит               | Логирование всех действий           |
