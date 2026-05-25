# arfs3arch — ARF S3arch (Windows Artifact Collector & Analyzer)

Research artifacts in Windows Systems.

Проект представляет собой минимальный MVP-инструмент для удалённого сбора артефактов Windows (браузерные данные, логи, recent и другие) и последующего анализа собранных данных (пакетный парсер логов, анализ UserAssist и классификация сервисов).

Основные компоненты

- `cli/cli.py` — operator CLI. Устанавливает SSH/SFTP-сессию (используется paramiko), деплоит PowerShell-скрипты на целевую машину, запускает модули сбора и скачивает итоговый ZIP.
- `runner/runner.ps1` — PowerShell-скрипт (runner) который выполняется на целевой Windows-машине и собирает артефакты в `output/`.
- `modules/` — папки с модулями сбора (`browser`, `logs`, `recent` и т.д.).
- `analyzer/` — модуль анализа: парсер собранных `logs.json`, декодер UserAssist и тестовый скрипт `test_logs.py`.
- `config/` — настройки и правила классификации (например `rules.yaml` используется парсером).

Быстрый старт (локально)

1. Создайте виртуальное окружение и установите зависимости:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r cli/requirements.txt
```

2. Запуск CLI (локально):

```bash
python3 cli/cli.py
```

CLI хранит цель в `cli/config/targets.json`.

Анализ собранных данных (локально)

1. Если у вас есть `logs.json` (например, в `output/old/.../logs.json`), можно запустить анализатор:

```bash
python3 analyzer/test_logs.py
```

2. Для запуска парсера напрямую:

```bash
python3 -c "from analyzer.parsers.logs_parser import LogsParser; print(LogsParser().parse('path/to/logs.json'))"
```

Структура вывода парсера

Парсер возвращает словарь с ключами: `metadata`, `services`, `user_assist`, `service_events`. Объекты `services` и `user_assist` уже содержат дополнительные поля: `hostname`, `username`, `collection_id`, `category`, `risk_score`, `tags`.

Безопасность и ответственность

Проект содержит инструменты удалённого выполнения и сбора данных. Используйте исключительно в пределах разрешённой тестовой среды или с явного разрешения владельца систем. Автономный запуск на чужих системах нарушает закон.

Лицензия

Проект поставляется с лицензией MIT (файл `LICENSE`).

Контакты и развитие

Если вы хотите продолжить разработку:
- Добавьте модуль тестирования для `analyzer`.
- Улучшите правила в `config/rules.yaml`.
- Добавьте CI (GitHub Actions) для тестов/линтинга.
