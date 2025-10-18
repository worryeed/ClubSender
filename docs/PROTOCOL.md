# Протокол X‑Poker (кратко)

Этот файл фиксирует минимально необходимую спецификацию TCP‑уровня, достаточную для работы клиента.

## Транспорт и кадры

- Соединение: TCP к игровому серверу (хост/порт берутся из ответа HTTP‑логина; значения по умолчанию в `core/constants.py`).
- Фрейминг: каждый пакет — 4‑байтовая длина (big‑endian) + полезная нагрузка (`payload`).

```text path=null start=null
frame := BE32(length) || payload
length := len(payload)
```

## Структура `payload`

- Начало: 2 байта — код типа сообщения (`msg_type_id`, u16 BE), затем 4 байта нулей.
- Далее ASCII‑строка команды вида `pk.<Name>REQ|RSP`.
- Затем разделитель `00 01`, бинарный protobuf‑подобный блок (wire 0/2) и 2‑байтовый номер последовательности (`seq`, BE) в конце.

```text path=null start=null
[length:4][msg_type:2][pad:4]["pk.*"][00 01][protobuf_payload][seq:2]
```

Сборка пакета реализована в `core/protocol.py::build_packet_correct`.

## Потоки сообщений

1) TCP‑логин
- `pk.UserLoginREQ (0x000f)` → ожидание `pk.UserLoginRSP`.
- После успеха запускаются message‑pump (чтение ответов) и heartbeat.

2) Heartbeat
- `pk.HBREQ (0x0008)` каждые ~3.0 s (±джиттер). Ответ `pk.HBRSP`.

3) Операции клуба (типичный сценарий)
- `pk.GetClubDescREQ (0x0011)` → `pk.GetClubDescRSP` (проверка существования клуба).
- `pk.ApplyClubREQ (0x000f)` → `pk.ApplyClubRSP` (статус заявки).

Дополнительные служебные запросы (по журналам клиента): `GetSelfData*, GetMoney*, GetClubDescList*` — используются для прогрева/синхронизации и реализованы в `core/client.py`.

## Поле сообщения заявки

- Сообщение передаётся как UTF‑8 (protobuf length‑delimited) в field 1 ApplyClubREQ.
- На практике сервер ограничивает размер по байтам (~до 120–128 байт). Для совместимости в GUI ограничение — 40 символов.

## Декодирование ответов

- `core/protobuf_decoder.py` содержит функции:
  - `decode_club_desc_response` — извлекает `club_info` (id, name, exists) из RSP.
  - `decode_apply_club_response` — извлекает коды статуса заявки; расшифровка кодов в `core/messages.py::decode_club_apply_status`.

## Прокси

- HTTP: прокси передаётся в `requests` через `XPokerAPI` (auto‑detect схемы).
- TCP: поддержка HTTP CONNECT и SOCKS5/SOCKS5h (`core/client.py`, `core/proxy_utils.py`).

Этого минимума достаточно, чтобы ориентироваться в структуре сообщений и точках расширения. Подробности — в исходниках `core/*.py`.