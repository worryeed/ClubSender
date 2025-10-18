# Обновления (PyUpdater)

Этот проект использует PyUpdater для проверки и загрузки обновлений.

## Хостинг
- GitHub Pages: ветка `gh-pages`, корень (`/`).
- URL манифеста: `https://worryeed.github.io/ClubSender/`.

## Версия приложения
- Файл: `core/version.py`, поле `__version__` (SemVer, например `1.0.0`).

## Генерация ключей (локально, вне репозитория)
```bash
pip install pyupdater
pyupdater init
pyupdater keys -c
```
Публичный ключ пропишите через переменную окружения `CLUBSENDER_PYU_PUBKEY` (или внесите в `update/updater.py` в `AppClientConfig.PUBLIC_KEY`).

## Сборка и публикация релиза
Вариант A (упакованный .exe через PyInstaller):
```bash
pip install pyinstaller pyupdater
pyinstaller --noconfirm --onefile --name ClubSender main.py
# Подготовка пакетов для PyUpdater
pyupdater build --app-version 1.0.1 ClubSender
pyupdater pkg -S   # подпись и подготовка к диплою
# В каталоге deploy/ — файлы для публикации. Залейте содержимое deploy/ в ветку gh-pages корень.
```

Вариант B (портативный zip со скриптами):
- Упакуйте необходимые файлы в zip и интегрируйте с PyUpdater аналогично, затем разместите на gh-pages.

## Работа клиента
- Кнопка "Проверить обновление" в GUI.
- Автопроверка при старте. Установка — только по подтверждению и без прерывания текущих задач.
