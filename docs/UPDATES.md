# Обновления (кастомный механизм + PyInstaller)

Приложение проверяет latest.json на GitHub Pages и скачивает новый .exe при наличии версии новее.

## Хостинг
- GitHub Pages: ветка `gh-pages`, корень (`/`).
- Манифест: `https://worryeed.github.io/ClubSender/latest.json`.

## Версия приложения
- Файл: `core/version.py`, поле `__version__` (SemVer, например `1.0.0`).

## Пример latest.json
```json
{
  "version": "1.0.1",
  "notes": "Minor fixes",
  "assets": {
    "windows": {
      "url": "https://worryeed.github.io/ClubSender/ClubSender-1.0.1.exe",
      "sha256": "<hex>"
    }
  }
}
```

## Релиз
1) Собрать `.exe` (PyInstaller):
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --name ClubSender main.py
```
2) Положить `ClubSender-<ver>.exe` и `latest.json` в корень ветки `gh-pages`.
3) Обновить `core/version.py` на эту же версию и запушить в `main`.

## Работа клиента
- Кнопка "Проверить обновление" в GUI.
- Автопроверка при старте. Для onefile на Windows: загрузит новый `.exe` и предложит заменить текущий (перезапуск через временный .bat).
