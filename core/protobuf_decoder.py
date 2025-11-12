"""
Декодер protobuf-сообщений для X-Poker TCP протокола.
Цель: корректно разбирать payload как реальных пакетов ("pk.*RSP$\x00\x08...")
так и тестовых искусственных пакетов ("... pk.*RSP ... \x00\x01 <payload>").
"""

import struct
from typing import Dict, Any, Optional, Tuple, List, Union


# -------------------------------
# Базовые примитивы protobuf
# -------------------------------

def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Декодировать varint (unsigned) из protobuf-потока.
    Возвращает (значение, новый_смещение).
    """
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 63:  # защитa от переполнения
            break
    return result, pos


def to_signed64(n: int) -> int:
    """Преобразовать беззнаковое значение varint в знаковое int64 (два дополнения)."""
    if n > 0x7FFFFFFFFFFFFFFF:
        return n - (1 << 64)
    return n


def decode_length_delimited(data: bytes, offset: int = 0) -> Tuple[bytes, int]:
    """Декодировать поле wire_type=2 (length-delimited)."""
    length, pos = decode_varint(data, offset)
    end = pos + length
    if end > len(data):
        return b"", pos
    return data[pos:end], end


def try_decode_utf8(b: bytes) -> Union[str, bytes]:
    """Попробовать декодировать как UTF-8, иначе вернуть сырой bytes."""
    try:
        return b.decode("utf-8")
    except Exception:
        return b


def parse_protobuf_fields(data: bytes, *, skip_leading_zeros: bool = False) -> Dict[int, List[Union[int, bytes, str, Dict]]]:
    """
    Простой парсер protobuf-полей: поддерживает wire_type 0 (varint) и 2 (length-delimited).
    Возвращает словарь {field_number: [values...]}, где values — int, str, bytes или вложенные dict.
    
    Если внутри length-delimited обнаружен вложенный protobuf, делаем попытку его рекурсивного разбора.
    """
    fields: Dict[int, List[Union[int, bytes, str, Dict]]] = {}
    i = 0
    if skip_leading_zeros:
        while i < len(data) and data[i] == 0x00:
            i += 1
    
    while i < len(data):
        # Пропускаем нулевые байты
        if i < len(data) and data[i] == 0x00:
            i += 1
            continue
            
        if i >= len(data):
            break
            
        tag = data[i]
        i += 1
        
        # Некорректные теги пропускаем
        if tag == 0x00:
            continue
            
        field_no = tag >> 3
        wire_type = tag & 0x07
        
        if field_no == 0:  # Некорректный field number
            continue
            
        if wire_type == 0:  # varint
            val, i = decode_varint(data, i)
            fields.setdefault(field_no, []).append(val)
        elif wire_type == 2:  # length-delimited
            chunk, i = decode_length_delimited(data, i)
            if not chunk:
                continue
                
            # Пытаемся распознать как вложенный protobuf
            # Проверяем, похоже ли на protobuf
            is_protobuf = False
            if len(chunk) > 0:
                first_byte = chunk[0]
                if first_byte != 0 and (first_byte & 0x07) in (0, 2):
                    # Попробуем распарсить
                    try:
                        nested = parse_protobuf_fields(chunk, skip_leading_zeros=False)
                        if nested:
                            fields.setdefault(field_no, []).append(nested)
                            is_protobuf = True
                    except:
                        pass
            
            if not is_protobuf:
                # Пробуем как строку
                s_or_b = try_decode_utf8(chunk)
                fields.setdefault(field_no, []).append(s_or_b)
        else:
            # Прочие wire types пропускаем
            if wire_type == 1:  # 64-bit
                i += 8
            elif wire_type == 5:  # 32-bit
                i += 4
            else:
                # Неизвестный тип - пропускаем байт
                pass
    
    return fields


# -------------------------------
# Поиск начала payload
# -------------------------------

def find_payload_start(response: bytes) -> int:
    """
    Найти начало payload в TCP-ответе.
    Реальный формат: после "pk.*RSP" идет '$' (0x24), затем 0x00 0x08, после чего payload.
    Возвращает индекс начала payload или -1.
    """
    # Найдем позицию "pk."
    pk_index = response.find(b"pk.")
    if pk_index == -1:
        return -1
    
    # Найти 'RSP' после 'pk.'
    rsp_index = response.find(b"RSP", pk_index)
    if rsp_index == -1:
        return -1
    
    # После RSP должен быть символ '$' (0x24)
    dollar_index = rsp_index + 3  # RSP = 3 байта
    if dollar_index >= len(response) or response[dollar_index] != 0x24:
        return -1
    
    # После '$' идут байты 0x00 0x08, затем payload
    payload_start = dollar_index + 3  # '$' + 0x00 + 0x08
    if payload_start > len(response):
        return -1
    
    return payload_start


# -------------------------------
# Декодирование ответов
# -------------------------------

def decode_apply_club_response(response: bytes) -> Dict[str, Any]:
    """
    Декодировать ответ ApplyClubRSP и вернуть максимально полную информацию.
    
    Формат ApplyClubRSP:
    1. Для успешных ответов и заявок: [club_id as varint][0x10][status][0x24][0x00]
       где club_id - varint (может быть 1-2 байта), 0x10 - field 2 type 0, status - значение
    2. Для ошибок (клуб не найден): другой формат с field 25 и field 2=1002
    """
    result: Dict[str, Any] = {
        "club_id": 0,
        "status": -1,
        "status_meaning": "Unknown",
        "message": "",
        "reason_text": "",  # извлеченная текстовая причина, если есть
        "raw_fields": {},
        "raw_hex": "",
    }

    start = find_payload_start(response)
    if start == -1:
        result["status_meaning"] = "Invalid response format"
        return result
    payload = response[start:]
    result["raw_hex"] = payload.hex()

    if not payload:
        result["status"] = -1
        result["status_meaning"] = "Empty response"
        result["message"] = "Пустой ответ"
        return result

    # Попробуем два формата декодирования
    
    # Формат 1: Начинается с club_id как varint
    try:
        club_id, pos = decode_varint(payload, 0)
        if pos > 0 and pos < len(payload) and payload[pos] == 0x10:  # field 2, wire_type 0
            # Это формат с club_id в начале
            result["club_id"] = club_id
            
            # Следующий байт после 0x10 - это status
            if pos + 1 < len(payload):
                status = payload[pos + 1]
                result["status"] = status
                
                if status == 0:
                    result["status_meaning"] = "Success"
                    result["message"] = "Успешно вступили в клуб"
                elif status == 1:
                    result["status_meaning"] = "Pending approval"
                    result["message"] = "Заявка ожидает одобрения"
                elif status == 2:
                    result["status_meaning"] = "Already member"
                    result["message"] = "Уже состоите в клубе"
                else:
                    result["status_meaning"] = f"Error (status={status})"
                    result["message"] = f"Ошибка: статус {status}"
                    
                # Также сохраним распарсенные поля для полноты
                result["raw_fields"] = parse_protobuf_fields(payload[pos:])
                return result
    except:
        pass
    
    # Формат 2: Стандартный protobuf
    fields = parse_protobuf_fields(payload)
    result["raw_fields"] = fields

    # Попробуем извлечь человекочитаемую причину (строки из payload)
    reason_text: str = ""
    try:
        for _fno, values in (fields or {}).items():
            for v in values or []:
                if isinstance(v, str):
                    # Отсекаем явные URL/пустые строки, берем самую длинную осмысленную
                    if (v.strip() and not v.strip().lower().startswith("http")):
                        if len(v) > len(reason_text):
                            reason_text = v.strip()
    except Exception:
        pass
    if reason_text:
        result["reason_text"] = reason_text
    
    # Проверка на ошибку "клуб не найден" - приоритетная
    # В ответе об ошибке field 2 содержит 1002, field 25 содержит дополнительный код
    if 2 in fields and fields[2] and fields[2][0] == 1002:
        result["status"] = 1002
        result["status_meaning"] = "Club not found"
        result["message"] = "Клуб не найден"
        # club_id может быть в field 25
        if 25 in fields and fields[25]:
            club_id_hint = fields[25][0]
            if isinstance(club_id_hint, int):
                result["club_id"] = club_id_hint
        return result
    
    # Field 15 может содержать club_id  
    if 15 in fields and fields[15]:
        if isinstance(fields[15][0], int):
            result["club_id"] = fields[15][0]
    
    # Field 2 содержит status
    if 2 in fields and fields[2]:
        status = fields[2][0]
        result["status"] = status
        
        if status == 0:
            result["status_meaning"] = "Success"
            result["message"] = "Успешно вступили в клуб"
        elif status == 1:
            result["status_meaning"] = "Pending approval"
            result["message"] = "Заявка ожидает одобрения"
        elif status == 2:
            result["status_meaning"] = "Already member"
            result["message"] = "Уже состоите в клубе"
        else:
            result["status_meaning"] = f"Error (status={status})"
            result["message"] = (reason_text or f"Ошибка: статус {status}")

    # Если статус не распознан, но есть причина — используем её
    if (not result.get("message")) and reason_text:
        result["message"] = reason_text

    return result


def decode_club_desc_response(response: bytes) -> Dict[str, Any]:
    """
    Декодировать ответ GetClubDescRSP и вернуть:
    - club_info: {club_id, club_name, exists, image_url}
    - top_fields: все верхнеуровневые поля (распарсенные) с рекурсией
    - raw_hex: hex payload для отладки
    """
    result: Dict[str, Any] = {
        "club_info": {
            "club_id": 0,
            "club_name": "",
            "exists": False,
            "image_url": "",
        },
        "top_fields": {},
        "raw_hex": "",
    }

    start = find_payload_start(response)
    if start == -1:
        return result
    payload = response[start:]
    result["raw_hex"] = payload.hex()

    if not payload:
        return result

    # Разбор всех верхнеуровневых полей
    top = parse_protobuf_fields(payload)
    result["top_fields"] = top
    
    # В реальных пакетах структура: field 3 содержит вложенный объект с информацией о клубе
    if 3 in top:
        for club_data in top[3]:
            if isinstance(club_data, dict):
                # club_id в field 2 (varint)
                if 2 in club_data and club_data[2]:
                    result["club_info"]["club_id"] = club_data[2][0]
                # club_name в field 3 (string)
                if 3 in club_data and club_data[3]:
                    name = club_data[3][0]
                    if isinstance(name, str):
                        result["club_info"]["club_name"] = name
                    elif isinstance(name, bytes):
                        result["club_info"]["club_name"] = name.decode('utf-8', errors='ignore')
                # image_url в field 5 (string)
                if 5 in club_data and club_data[5]:
                    url = club_data[5][0]
                    if isinstance(url, str):
                        result["club_info"]["image_url"] = url
                    elif isinstance(url, bytes):
                        result["club_info"]["image_url"] = url.decode('utf-8', errors='ignore')
    
    # Альтернативный поиск, если структура другая
    if not result["club_info"]["club_name"]:
        # Поиск строк напрямую в payload
        # Ищем строки, которые могут быть названием клуба
        for field_no, values in top.items():
            for val in values:
                if isinstance(val, str) and len(val) > 2 and not val.startswith('http'):
                    # Возможно это название клуба
                    if not result["club_info"]["club_name"]:
                        result["club_info"]["club_name"] = val
                elif isinstance(val, str) and val.startswith('http'):
                    result["club_info"]["image_url"] = val
    
    # Определяем существует ли клуб
    # Клуб существует если есть хотя бы название
    if result["club_info"]["club_name"]:
        result["club_info"]["exists"] = True

    return result


# -------------------------------
# Класс-обертка совместимости
# -------------------------------
class ProtobufDecoder:
    @staticmethod
    def decode_apply_club_response(data: bytes) -> Dict[str, Any]:
        return decode_apply_club_response(data)

    @staticmethod
    def decode_club_desc_response(data: bytes) -> Dict[str, Any]:
        return decode_club_desc_response(data)
