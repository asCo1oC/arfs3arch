# ARFSearch v2 (WinRM)

Краткое описание
- ARFSearch v2 — инструмент для удалённого сбора артефактов с Windows через WinRM.
- Основная транспортная реализация: [`WinRMTransport`](cli/transport/winrm_transport.py).
- Поддерживаются два метода передачи больших файлов:
  - Через локальный HTTP-сервер ([tools/http_server.py](tools/http_server.py)) — автоматически стартует при необходимости.
  - Пошаговая (chunked) загрузка base64 через WinRM (fallback) — реализована в [`WinRMTransport._upload_file_chunked`](cli/transport/winrm_transport.py).

Основные файлы и символы
- Транспорт и загрузчики:
  - [`WinRMTransport`](cli/transport/winrm_transport.py)
  - [`WinRMTransport._ensure_http_server`](cli/transport/winrm_transport.py)
  - [`WinRMTransport._download_via_http_server`](cli/transport/winrm_transport.py)
  - [`WinRMTransport._upload_file_chunked`](cli/transport/winrm_transport.py)
- CLI:
  - [cli/cli.py](cli/cli.py) — основной пользовательский интерфейс и точка входа.
- Инструмент для отдачи файлов по HTTP:
  - [tools/http_server.py](tools/http_server.py)
- Runner:
  - [runner/runner.ps1](runner/runner.ps1) — скрипт, разворачиваемый на целевой машине.
- Модули и результаты:
  - [modules/](modules/) — коллекции модулей (browser, logs, recent и т.д.)
  - [output/](output/) — локальная директория, куда сохраняются скачанные архивы.

Ключевые возможности (реализовано в коде)
- Автоподключение по WinRM: в [`WinRMTransport.__init__`](cli/transport/winrm_transport.py) создаётся сессия через pywinrm.
- Развёртывание: [`WinRMTransport.deploy`](cli/transport/winrm_transport.py) копирует runner и каталоги modules -> remote.
- Передача больших файлов:
  - Если файл > 500 KB (константа LARGE_FILE_THRESHOLD), пытается раздать файл через локальный HTTP-сервер ([tools/http_server.py](tools/http_server.py)) и скачать его на удалённой машине (`_download_via_http_server`).
  - При неудаче используется chunked base64-аплоад (`_upload_file_chunked`).
- Получение результатов: [`WinRMTransport.retrieve_archive`](cli/transport/winrm_transport.py) читает последний .zip в удалённой output-папке, кодирует в base64 и сохраняет локально.
- Очистка: [`WinRMTransport.cleanup`](cli/transport/winrm_transport.py) удаляет staging-папку на удалённой машине и при необходимости останавливает HTTP-сервер.

Как пользоваться (кратко)
1. Убедиться в установленных зависимостях (см. requirements.txt).
2. Настроить цель в [config/targets.json](config/targets.json) / настройки в [config/settings.json](config/settings.json). Параметры, важные для работы HTTP-сервера:
   - http_listen_address / http_port для `WinRMTransport` (используется при connect в [cli/cli.py](cli/cli.py)).
   - http_server_auto_stop — автоматически останавливать сервер при завершении.
3. Запустить CLI:
```sh
python [cli.py](http://_vscodecontentref_/1)
