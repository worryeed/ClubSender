# PPPoker: регистрация и логин — формирование полей

Коротко:
- t — это UNIX epoch (секунды). t10 = mmddHHMMSS по часовому поясу Пекин (UTC+8).
- Ключ XXTEA: key16 = (t10 + 'd56590') в ASCII (ровно 16 байт).
- Пароль (и в register.php, и в login.php) — это XXTEA(includeLength) шифрование двойного MD5 пароля:
  1) crypto_password_hex = md5(md5(password).hexdigest()).hexdigest().lower()  # строка на 32 hex-символа
  2) payload = ASCII(crypto_password_hex) + LE32(len(crypto_password_hex))
  3) cipher = XXTEA(payload, key16) в little‑endian словах; base64(cipher) → password
- Имя пользователя в register.php (username) — тоже XXTEA(includeLength) от UTF-8(username) с тем же key16 и base64. В login.php username отправляется в открытом виде.

## Детали

### Временная метка
- В запросах присутствует `t` (epoch). Для ключа берётся `t10 = strftime("%m%d%H%M%S", gmtime(t + 8*3600))`. 
- Ключ всегда: `key16 = (t10 + 'd56590').encode('ascii')` (16 байт).

### XXTEA includeLength (упаковка и шифрование)
- Упаковка `includeLength`:
  - Разбить данные на 4‑байтовые слова LE; дополнить нулями до кратности 4 (только в последнем 32‑битном слове).
  - Добавить в конец 32‑битное little‑endian число — исходную длину данных (до паддинга).
- XXTEA выполняется над u32 массивом; DELTA = 0x9E3779B9; стандартные раунды: `q = 6 + 52 // n`.
- Результат сериализуется обратно в LE и кодируется base64.

### Пароль (для login.php и register.php)
1) `crypto_password_hex = md5( md5(password).hexdigest().lower() ).hexdigest().lower()`
2) `enc_password = base64( XXTEA( ASCII(crypto_password_hex) + LE32(len), key16 ) )`

### Имя пользователя в register.php
- `enc_username = base64( XXTEA( UTF8(username) + LE32(len), key16 ) )`
- В `login.php` поле `username` — открытый текст (без шифрования).

### HTTP запросы

Регистрация (GET): `/poker/api/register.php`
- Важные параметры:
  - `username` — enc_username (см. выше)
  - `password` — enc_password (см. выше)
  - `t` — epoch (сек)
  - `os` — `WindowsPlayer`
  - `appid` — `globle`
  - `clientvar` — динамическая версия клиента (запрашивается у серверов версии)
  - `imei` — 40‑символьный hex (см. ниже)
  - `app_type` — `1`

Логин (POST): `/poker/api/login.php`
- Поля формы (основные):
  - `type=4`, `region=2`, `code=''`
  - `username` — простой текст (логин)
  - `password` — enc_password (см. выше)
  - `t` — epoch
  - `os=windows`, `appid=globle`, `clientvar=<серверная версия>`
  - `imei` — 40‑символьный hex (см. ниже)
  - и прочие служебные (`device_token`, `platform_type=1` и т.п.)

### IMEI (ограничения / нормализация)
- В клиенте используется 40‑символьная hex‑строка — это `sha1(device_id)` в hex нижним регистром.
- Внутри ClubSender: если `device_id` пустой — генерируется UUID4 и берётся `sha1(uuid_str).hexdigest()`.

### TCP вход (после login)
- Сервер возвращает: `uid`, `rdkey` (token), адрес ворот `gserver_ip:port`.
- TCP `pb.UserLoginREQ` содержит: uid, token (rdkey), clientver, os, platform_type, entry, country.

## Псевдокод (Python‑стиль)

Пароль:
```python
import hashlib, base64

DELTA = 0x9E3779B9

def t10_from_epoch_beijing(t):
    import time
    return time.strftime('%m%d%H%M%S', time.gmtime(t + 8*3600))

def xxtea_includelen_encrypt(data_bytes: bytes, key16: bytes) -> bytes:
    # pack includeLength
    n = (len(data_bytes) + 4 + 3) // 4
    data_len = (n - 1) * 4
    buf = data_bytes + b'\x00' * (data_len - len(data_bytes))
    v = [int.from_bytes(buf[i:i+4], 'little') for i in range(0, len(buf), 4)]
    v.append(len(data_bytes))
    k = [int.from_bytes(key16[i:i+4], 'little') for i in range(0, 16, 4)]
    # xxtea rounds
    z = v[-1]; s = 0; q = 6 + 52 // len(v)
    for _ in range(q):
        s = (s + DELTA) & 0xffffffff; e = (s >> 2) & 3
        for p in range(len(v)-1):
            y = v[p+1]
            mx = (((z>>5) ^ (y<<2)) + ((y>>3) ^ (z<<4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] + mx) & 0xffffffff; z = v[p]
        y = v[0]
        mx = (((z>>5) ^ (y<<2)) + ((y>>3) ^ (z<<4))) ^ ((s ^ y) + (k[((len(v)-1) & 3) ^ e] ^ z))
        v[-1] = (v[-1] + mx) & 0xffffffff; z = v[-1]
    return b''.join(x.to_bytes(4, 'little') for x in v)

def encrypt_password_exact(password: str, epoch: int) -> str:
    md5_1 = hashlib.md5(password.encode('utf-8')).hexdigest().lower()
    crypto = hashlib.md5(md5_1.encode('ascii')).hexdigest().lower()
    key16 = (t10_from_epoch_beijing(epoch) + 'd56590').encode('ascii')
    payload = crypto.encode('ascii') + len(crypto).to_bytes(4, 'little')
    return base64.b64encode(xxtea_includelen_encrypt(payload, key16)).decode('ascii')
```

Username для register.php:
```python
def encrypt_username_exact(username: str, epoch: int) -> str:
    key16 = (t10_from_epoch_beijing(epoch) + 'd56590').encode('ascii')
    payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
    return base64.b64encode(xxtea_includelen_encrypt(payload, key16)).decode('ascii')
```

## Почему именно суффикс ключа 'd56590'
- Это захардкоженная константа в клиенте PPPoker. В пути логина для пароля (login.php) она используется при построении ключа XXTEA: key16 = t10 + 'd56590'.
- Регистрация (register.php) переиспользует тот же криптомодуль: для поля username используется тот же самый ключ. 
- Практическое подтверждение:
  - При расшифровке 24‑байтовых username из реальных запросов с ключом (t10+'d56590') получаем UTF‑8 исходного логина и LE‑длину на конце (includeLength).
  - Иная соль не даёт детерминированного совпадения.
- Технический смысл суффикса — дополнить t10 (10 байт) до 16‑байтового ключа и выступать «солью». Исторически это константа из клиента; публичной спецификации нет.

## Примечания эксплуатации
- Для register.php полезно сделать предзапрос к `/` (cookie `aliyungf_tc`), как это делает официальный клиент.
- На уровне API встречаются лимиты по IP; при кодах `-1/-2/10000044/20010029` стоит ротировать прокси.
- `clientvar` лучше забирать с серверов версий (`/poker/api/version.php` и родственные) — в ClubSender это уже реализовано.
