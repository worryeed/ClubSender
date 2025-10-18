"""Модуль с русскими переводами сообщений для XPoker GUI."""

from typing import Dict, Any

# Визуальные индикаторы
class Icons:
    SUCCESS = "✅"       # Успех
    ERROR = "❌"         # Ошибка
    WARNING = "⚠️"      # Предупреждение
    INFO = "ℹ️"         # Информация
    PROCESS = "🔄"      # Процесс выполняется
    NETWORK = "🌐"      # Сетевые операции
    AUTH = "🔐"         # Авторизация
    CLUB = "🏛️"        # Операции с клубами
    TCP = "🔌"          # TCP соединение
    TARGET = "🎯"       # Целевые действия
    CELEBRATION = "🎉"  # Успешное завершение

# Переводы статусов клубов
CLUB_STATUS_MESSAGES = {
    0: "Заявка успешно отправлена",
    1: "Ожидает одобрения",
    2: "Уже состоит в клубе", 
    3: "Клуб заполнен",
    4: "Заявка отклонена",
    5: "Заблокирован в клубе",
    -1: "❓ Неизвестный статус",
    "unknown": "❓ Неизвестный статус",
    "club_not_found": "❌ Клуба не существует",
    "invalid_club_id": "❌ Неверный ID клуба",
    "network_error": "❌ Ошибка сети"
}

# Переводы основных сообщений
MESSAGES = {
    # Авторизация
    "login_start": "🔐 Начинаем авторизацию",
    "login_success": "✅ Авторизация успешна",
    "login_failed": "❌ Ошибка авторизации",
    "login_no_token": "⚠️ Токен не получен",
    "login_uid_found": "ℹ️ UID получен",
    "login_uid_missing": "⚠️ UID не найден",
    
    # TCP соединение
    "tcp_connect_start": "🔌 Устанавливаем TCP соединение",
    "tcp_connect_success": "✅ TCP соединение установлено",
    "tcp_connect_failed": "❌ Ошибка TCP соединения",
    "tcp_auth_start": "🔐 TCP авторизация",
    "tcp_auth_success": "✅ TCP авторизация успешна",
    "tcp_auth_failed": "❌ Ошибка TCP авторизации",
    
    # Операции с клубами
    "club_desc_start": "🏛️ Получаем описание клуба",
    "club_desc_success": "✅ Описание клуба получено",
    "club_desc_failed": "⚠️ Не удалось получить описание клуба",
    "club_apply_start": "🎯 Подаем заявку в клуб",
    "club_apply_success": "🎉 Успешно вступили в клуб",
    "club_apply_failed": "❌ Заявка в клуб отклонена",
    "club_already_member": "ℹ️ Уже состоит в клубе",
    "club_not_found": "❌ Клуб не существует",
    
    # Общие сообщения
    "process_interrupted": "⚠️ Процесс прерван пользователем",
    "unknown_error": "❌ Неизвестная ошибка",
    "invalid_club_id": "❌ Неверный формат ID клуба"
}

def get_club_status_message(status_code: int, club_exists: bool = True, club_id: str = "") -> str:
    """
    Получить русское сообщение для статуса вступления в клуб.
    
    Args:
        status_code: Код статуса
        club_exists: Существует ли клуб
        club_id: ID клуба (не используется в универсальной обработке)
        
    Returns:
        Русское сообщение со статусом
    """
    # Универсальная обработка несуществующих клубов по статусу
    if not club_exists or status_code == -1 or status_code == 1002:
        return CLUB_STATUS_MESSAGES["club_not_found"]
    
    return CLUB_STATUS_MESSAGES.get(status_code, CLUB_STATUS_MESSAGES["unknown"])

def format_join_result(username: str, club_id: str, success: bool, message: str) -> str:
    """
    Форматировать результат проверки клуба с индикаторами.
    
    Мы не утверждаем немедленное вступление — показываем упрощённый статус наличия клуба.
    
    Args:
        username: Имя пользователя
        club_id: ID клуба
        success: Успешность операции (True = клуб существует/доступен)
        message: Оригинальное сообщение (используется только для отмены/ошибок сети)
        
    Returns:
        Отформатированное сообщение
    """
    m = (message or "").strip()
    # Отдельный случай: отмена
    if not success and ("Cancel" in m or "Отмен" in m):
        icon = Icons.WARNING
        text = "Отменено"
        return f"{icon} [{username}] → Клуб {club_id}: {text}"
    # Основная логика отображения
    icon = Icons.SUCCESS if success else Icons.ERROR
    text = "Клуб есть" if success else "Клуба нет"
    return f"{icon} [{username}] → Клуб {club_id}: {text}"

def format_tcp_step(step_name: str, success: bool, details: str = "") -> str:
    """
    Форматировать сообщение о шаге TCP операции.
    
    Args:
        step_name: Название шага
        success: Успешность выполнения
        details: Дополнительные детали
        
    Returns:
        Отформатированное сообщение
    """
    icon = Icons.SUCCESS if success else Icons.ERROR
    msg = f"{icon} {step_name}"
    if details:
        msg += f": {details}"
    return msg

def format_login_step(username: str, step: str, success: bool, details: str = "") -> str:
    """
    Форматировать сообщение о шаге авторизации.
    
    Args:
        username: Имя пользователя  
        step: Название шага
        success: Успешность выполнения
        details: Дополнительные детали
        
    Returns:
        Отформатированное сообщение
    """
    icon = Icons.SUCCESS if success else Icons.ERROR
    msg = f"{icon} [{username}] {step}"
    if details:
        msg += f": {details}"
    return msg

# Статусы ответов от сервера для отладки
def decode_club_apply_status(status_code: int) -> Dict[str, Any]:
    """
    Расшифровать статус ответа на заявку в клуб.
    
    Args:
        status_code: Код статуса (int или str-число)
        
    Returns:
        Словарь с информацией о статусе
    """
    status_map = {
        0: {
            "success": True,
            "icon": Icons.CELEBRATION,
            "message": "Заявка успешно отправлена",
            "description": "Вы успешно подали заявку на вступление в клуб"
        },
        1: {
            "success": True, 
            "icon": Icons.INFO,
            "message": "Заявка ожидает одобрения",
            "description": "Заявка отправлена, ожидается решение администратора клуба"
        },
        2: {
            "success": True,
            "icon": Icons.INFO, 
            "message": "Уже состоит в клубе",
            "description": "Пользователь уже является членом этого клуба"
        },
        3: {
            "success": False,
            "icon": Icons.WARNING,
            "message": "Клуб заполнен",
            "description": "В клубе достигнуто максимальное количество участников"
        },
        4: {
            "success": False,
            "icon": Icons.ERROR,
            "message": "Заявка отклонена", 
            "description": "Администратор клуба отклонил заявку на вступление"
        },
        5: {
            "success": False,
            "icon": Icons.ERROR,
            "message": "Заблокирован в клубе",
            "description": "Пользователь заблокирован в этом клубе"
        },
        -1: {
            "success": False,
            "icon": Icons.ERROR,
            "message": "❌ Клуба не существует",
            "description": "Указанный клуб не найден или недоступен"
        },
        # Универсальная обработка статуса "клуб не существует"
        1002: {
            "success": False,
            "icon": Icons.ERROR,
            "message": "❌ Клуба не существует", 
            "description": "Клуб не найден или недоступен (статус 1002)"
        }
    }
    
    # Защита от строкового кода статуса
    try:
        code = int(status_code)
    except Exception:
        code = status_code
    
    return status_map.get(code, {
        "success": False,
        "icon": Icons.WARNING,
        "message": "❓ Неизвестный статус",
        "description": f"Получен неизвестный статус {status_code}"
    })
