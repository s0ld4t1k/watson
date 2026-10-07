#!/usr/bin/env python3
"""Watson: evidence-first OSINT triage for scam reports.

Public web checks and Telegram data visible to the authenticated user are
summarised as leads, never as proof of identity. No private data is acquired;
locally supplied investigation evidence may be processed and correlated.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import re
import socket
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


CACHE_DB = Path.home() / ".watson_cache.sqlite"
CACHE_TTL = 6 * 3600
UA = {"User-Agent": "Watson-OSINT/1.0"}


def new_report(kind: str, target: str) -> dict:
    return {"type": kind, "target": target, "findings": [], "flags": [], "links": [], "notes": [], "indicators": {}}


def add(rep: dict, label: str, value) -> None:
    if value not in (None, "", [], {}):
        rep["findings"].append((label, str(value)))


def remember(rep: dict, kind: str, values) -> None:
    if isinstance(values, str):
        values = [values]
    rep["indicators"][kind] = sorted({str(value) for value in values if value})


def flag(rep: dict, points: int, reason: str) -> None:
    rep["flags"].append((points, reason))


def risk(rep: dict) -> tuple[int, str]:
    score = sum(points for points, _ in rep["flags"])
    return score, "низкий" if score <= 1 else "средний" if score <= 4 else "высокий"


def days_ago(value: str | None) -> int | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return (dt.datetime.now(dt.timezone.utc) - parsed).days
    except (AttributeError, TypeError, ValueError):
        return None


def cache_db() -> sqlite3.Connection:
    con = sqlite3.connect(CACHE_DB)
    con.execute("CREATE TABLE IF NOT EXISTS c (url TEXT PRIMARY KEY, status INT, body TEXT, ts REAL)")
    return con


def fetch(url: str, ttl: int = CACHE_TTL, timeout: int = 12) -> tuple[int, str]:
    """Cached GET using only the standard library."""
    con = cache_db()
    row = con.execute("SELECT status, body, ts FROM c WHERE url=?", (url,)).fetchone()
    if row and time.time() - row[2] < ttl:
        con.close()
        return row[0], row[1]
    try:
        request = Request(url, headers=UA)
        with urlopen(request, timeout=timeout) as response:
            status, body = response.status, response.read().decode("utf-8", "replace")
    except (HTTPError, URLError, TimeoutError, OSError):
        con.close()
        return 0, ""
    if status < 500:
        con.execute("REPLACE INTO c VALUES (?,?,?,?)", (url, status, body, time.time()))
        con.commit()
    con.close()
    return status, body


def fetch_json(url: str, **kwargs):
    status, body = fetch(url, **kwargs)
    try:
        return status, json.loads(body)
    except (TypeError, ValueError):
        return status, None


# Local Telegram export mode -------------------------------------------------
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
URL_RE = re.compile(r"https?://[^\s<>]+|(?<!\w)t\.me/[A-Za-z0-9_/?=-]+", re.I)
USERNAME_RE = re.compile(r"(?<!\w)@[A-Za-z0-9_]{4,}")
EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])", re.I)
ID_RE = re.compile(r"(?i)(?:telegram|user|account|клиент|аккаунт)?[_\s-]*id\s*[:#=]?\s*(-?\d{5,14})")
SIGNALS = {
    "urgency": re.compile(r"срочно|немедленно|только сегодня|последн(?:ий|яя) шанс|urgent|now|limited time", re.I),
    "payment_request": re.compile(r"перевед|оплат|комисс|предоплат|карта|кошел[её]к|крипт|bitcoin|usdt|payment|send money", re.I),
    "credential_request": re.compile(r"парол|код из смс|код подтвержден|одноразов|логин|password|verification code|seed phrase", re.I),
    "impersonation": re.compile(r"служба безопасност|поддержк[аи]|банк|полици|налогов|администратор|security team|support", re.I),
    "off_platform": re.compile(r"whatsapp|вотсап|signal|viber|перейд[иите]|напиши в|write me on", re.I),
}


def message_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(
            part if isinstance(part, str) else str(part.get("text", "")) if isinstance(part, dict) else ""
            for part in value
        )
    return ""


def load_export(path: Path) -> tuple[dict, list[dict]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"не удалось прочитать JSON-экспорт: {exc}") from exc
    if isinstance(data, list):
        return {"name": path.stem}, [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict) or not isinstance(data.get("messages"), list):
        raise ValueError("ожидался Telegram JSON-экспорт с массивом 'messages'")
    return data, [item for item in data["messages"] if isinstance(item, dict)]


def export_indicators(text: str) -> dict[str, list[str]]:
    return {
        "phones": sorted(set(PHONE_RE.findall(text))),
        "urls": sorted(set(URL_RE.findall(text))),
        "usernames": sorted(set(USERNAME_RE.findall(text))),
        "emails": sorted(set(EMAIL_RE.findall(text))),
        "ids": sorted(set(ID_RE.findall(text))),
    }


def scan_evidence(target: str) -> dict:
    path = Path(target).expanduser()
    rep = new_report("Предоставленное доказательство", str(path))
    try:
        raw = path.read_bytes()
    except OSError as exc:
        rep["notes"].append(f"Не удалось прочитать материал: {exc}")
        return rep
    text = raw.decode("utf-8", "replace")
    add(rep, "Размер файла", len(raw))
    add(rep, "SHA-256", hashlib.sha256(raw).hexdigest())
    add(rep, "Формат", path.suffix.lower().lstrip(".") or "текст")
    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
            add(rep, "JSON-записей", len(payload) if isinstance(payload, (list, dict)) else 0)
        except json.JSONDecodeError:
            rep["notes"].append("Файл имеет расширение JSON, но не распознан как корректный JSON.")
    elif path.suffix.lower() == ".csv":
        try:
            add(rep, "CSV-строк", max(0, sum(1 for _ in csv.reader(text.splitlines())) - 1))
        except csv.Error as exc:
            rep["notes"].append(f"CSV не удалось разобрать: {exc}")
    indicators = export_indicators(text)
    rep["indicators"] = indicators
    for name, values in indicators.items():
        add(rep, f"Найденные {name}", ", ".join(values))
    rep["notes"].append("Материал прочитан локально; Watson не получает по нему новые закрытые данные.")
    rep["notes"].append("Совпадения являются следственными зацепками и требуют проверки источника и контекста.")
    return rep


def scan_export_from_messages(messages: list[dict]) -> dict:
    rep = new_report("Telegram-экспорт", "self-test")
    for message in messages:
        text = message_text(message.get("text"))
        hits = [name for name, pattern in SIGNALS.items() if pattern.search(text)]
        if hits:
            flag(rep, min(30, 3 * len(hits)), f"Сообщение {message.get('id', '?')}: {', '.join(hits)}")
    rep["indicators"] = export_indicators("\n".join(message_text(item.get("text")) for item in messages))
    return rep


def scan_export(target: str) -> dict:
    path = Path(target).expanduser()
    _, messages = load_export(path)
    rep = new_report("Telegram-экспорт", str(path))
    counts = {name: 0 for name in SIGNALS}
    matches = []
    all_text = "\n".join(message_text(item.get("text")) for item in messages)
    for message in messages:
        text = " ".join(message_text(message.get("text")).split())
        hits = [name for name, pattern in SIGNALS.items() if pattern.search(text)]
        if not hits:
            continue
        for hit in hits:
            counts[hit] += 1
        matches.append((message.get("id", "?"), message.get("date", ""), message.get("from") or message.get("from_id", "unknown"), ", ".join(hits), text[:320]))
        flag(rep, min(30, 3 * len(hits)), f"Сообщение {message.get('id', '?')}: {', '.join(hits)}")
    add(rep, "Сообщений проверено", len(messages))
    add(rep, "Сообщений с сигналами", len(matches))
    rep["indicators"] = export_indicators(all_text)
    for name, values in rep["indicators"].items():
        add(rep, f"Наблюдаемые {name}", ", ".join(values))
    for message_id, date, sender, hits, excerpt in matches:
        add(rep, f"Улика #{message_id}", f"{date} | {sender} | {hits} | {excerpt}")
    rep["notes"].append("Сводка построена только по содержимому переданного экспорта; это не установление личности.")
    return rep


# Public Telegram page and optional Telethon mode ----------------------------
SCAM_WORDS = ["инвест", "заработ", "крипт", "гарант", "депозит", "вывод средств", "сигнал", "пассивный доход", "удалённ", "удаленн", "без вложений", "ставки", "прогноз"]
IMPERSONATION = ["support", "поддержка", "admin", "админ", "official", "менеджер", "bank", "банк", "garant", "гарант", "helper", "service"]


def meta_tag(body: str, prop: str) -> str:
    match = re.search(r'<meta property="%s" content="([^"]*)"' % re.escape(prop), body)
    return html.unescape(match.group(1)) if match else ""


def telegram_slug(target: str) -> str:
    return re.sub(r"^(https?://)?(t\.me/|telegram\.me/)?@?", "", target.strip()).split("/")[0].split("?")[0]


def scan_telegram(target: str) -> dict:
    username = telegram_slug(target)
    rep = new_report("Telegram", "@" + username)
    remember(rep, "usernames", username)
    status, body = fetch(f"https://t.me/{username}")
    if status != 200:
        rep["notes"].append(f"t.me вернул статус {status}; публичная страница недоступна.")
        return rep
    title, description = meta_tag(body, "og:title"), meta_tag(body, "og:description")
    exists = bool(title and title != f"Telegram: Contact @{username}")
    add(rep, "Существует (эвристика)", "да" if exists else "не найден или скрыт")
    if not exists:
        rep["notes"].append("Аккаунт мог быть удалён, переименован или заблокирован.")
    else:
        add(rep, "Имя", title)
        add(rep, "Описание (bio)", description)
        extra = re.search(r'tgme_page_extra">([^<]+)', body)
        if extra:
            add(rep, "Доп. информация", html.unescape(extra.group(1)).strip())
        kind = "бот" if username.lower().endswith("bot") else "канал/группа" if extra and re.search(r"subscribers|members|подпис|участ", extra.group(1), re.I) else "пользователь"
        add(rep, "Тип (эвристика)", kind)
        low = f"{title} {description}".lower()
        hits = [word for word in SCAM_WORDS if word in low]
        if hits:
            flag(rep, min(3, len(hits)), "Характерные слова в имени/bio: " + ", ".join(hits))
        impersonation = [word for word in IMPERSONATION if word in f"{title} {username}".lower()]
        if impersonation:
            flag(rep, 2, "Похож на выдачу себя за поддержку/официальное лицо: " + ", ".join(impersonation))
        if re.search(r"t\.me/\+|joinchat|bit\.ly|tinyurl", description, re.I):
            flag(rep, 1, "В bio есть ссылка-перенаправление")
    rep["notes"].append("Публичная страница не подтверждает принадлежность аккаунта конкретному человеку.")
    rep["links"] += [("Профиль t.me", f"https://t.me/{username}"), ("Поиск ника в Google", f"https://www.google.com/search?q={quote(chr(34) + username + chr(34))}"), ("Поиск ника в Яндексе", f"https://yandex.ru/search/?text={quote(chr(34) + username + chr(34))}")]
    return rep


ID_ANCHORS = [(2_768_409, "2013-11"), (100_000_000, "2015-03"), (500_000_000, "2018-01"), (1_000_000_000, "2019-12"), (2_000_000_000, "2020-12"), (5_000_000_000, "2021-11"), (6_000_000_000, "2022-10"), (7_000_000_000, "2023-09")]


def load_anchors():
    path = Path.home() / ".watson_anchors.json"
    if path.exists():
        try:
            return sorted((int(item[0]), item[1]) for item in json.loads(path.read_text()))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            pass
    return ID_ANCHORS


def estimate_age(uid: int) -> tuple[str, bool]:
    anchors = load_anchors()
    if uid > anchors[-1][0]:
        return f"новее {anchors[-1][1]} (выше последней точки)", True
    for (first_id, first_date), (second_id, second_date) in zip(anchors, anchors[1:]):
        if first_id <= uid <= second_id:
            return f"между {first_date} и {second_date}", False
    return f"старше {anchors[0][1]}", False


def scan_id(target: str) -> dict:
    value = target.strip()
    try:
        uid = int(value)
    except ValueError:
        rep = new_report("Telegram ID", value)
        rep["notes"].append("ID должен быть целым числом.")
        return rep
    rep = new_report("Telegram ID", value)
    remember(rep, "ids", value)
    add(rep, "ID", uid)
    if uid > 0:
        estimate, newer = estimate_age(uid)
        add(rep, "Примерная дата регистрации", estimate)
        if newer:
            flag(rep, 2, "ID выше последней калибровочной точки; аккаунт может быть свежим")
    else:
        add(rep, "Тип", "служебный ID группы/канала (эвристика)")
    rep["links"].append(("Открыть Telegram", f"tg://openmessage?user_id={uid}"))
    rep["notes"].append("Дата регистрации приблизительная: Telegram не предоставляет её напрямую по ID.")
    return rep


def telegram_status(status) -> str:
    return {"UserStatusOnline": "онлайн", "UserStatusRecently": "недавно (скрыто настройками)", "UserStatusLastWeek": "на этой неделе (скрыто)", "UserStatusLastMonth": "в этом месяце (скрыто)", "UserStatusOffline": "офлайн (время открыто)", "UserStatusEmpty": "давно или скрыто"}.get(type(status).__name__, "неизвестно")


def deep_telegram(rep: dict, username: str) -> None:
    import os

    try:
        from telethon.sync import TelegramClient
        from telethon import errors
        from telethon.tl.functions.messages import GetCommonChatsRequest
        from telethon.tl.functions.users import GetFullUserRequest
        from telethon.tl.types import User
    except ImportError:
        rep["notes"].append("Для --deep установите Telethon: pip install telethon")
        return
    api_id, api_hash = os.getenv("WATSON_TG_API_ID"), os.getenv("WATSON_TG_API_HASH")
    if not (api_id and api_hash):
        rep["notes"].append("Для --deep задайте WATSON_TG_API_ID и WATSON_TG_API_HASH с my.telegram.org.")
        return
    try:
        with TelegramClient(str(Path.home() / ".watson"), int(api_id), api_hash) as client:
            entity = client.get_entity(int(username) if re.fullmatch(r"-?\d+", username) else username)
            add(rep, "[API] ID", entity.id)
            if isinstance(entity, User):
                estimate, newer = estimate_age(entity.id)
                add(rep, "[API] Возраст по ID (грубо)", estimate)
                add(rep, "[API] Имя", " ".join(x for x in (entity.first_name, entity.last_name) if x))
                add(rep, "[API] Доп. usernames", ", ".join(x.username for x in (entity.usernames or []) if x.username))
                add(rep, "[API] Бот / Premium / Verified", f"{'да' if entity.bot else 'нет'} / {'да' if entity.premium else 'нет'} / {'да' if entity.verified else 'нет'}")
                add(rep, "[API] Последний визит", telegram_status(entity.status))
                full = client(GetFullUserRequest(entity)).full_user
                add(rep, "[API] Bio", full.about)
                add(rep, "[API] Фото профиля", "есть" if full.profile_photo else "нет")
                common = getattr(full, "common_chats_count", 0) or 0
                add(rep, "[API] Общих групп", common)
                if common:
                    chats = client(GetCommonChatsRequest(user_id=entity, max_id=0, limit=50)).chats
                    add(rep, "[API] Общие группы", "; ".join(chat.title for chat in chats))
                if entity.scam:
                    flag(rep, 5, "Telegram сам пометил аккаунт как SCAM")
                if entity.fake:
                    flag(rep, 5, "Telegram сам пометил аккаунт как FAKE")
                if newer:
                    flag(rep, 2, "ID выше последней калибровочной точки; аккаунт может быть свежим")
            else:
                add(rep, "[API] Название", getattr(entity, "title", ""))
                created = getattr(entity, "date", None)
                if created:
                    add(rep, "[API] Создан(а)", str(created)[:10])
                    age = (dt.datetime.now(dt.timezone.utc) - created).days
                    if age < 30:
                        flag(rep, 2, f"Канал/группа создан(а) {age} дн. назад")
                try:
                    add(rep, "[API] Участников", client.get_participants(entity, limit=0).total)
                except Exception:
                    pass
                if getattr(entity, "scam", False) or getattr(entity, "fake", False):
                    flag(rep, 5, "Telegram пометил канал/группу как SCAM/FAKE")
    except (errors.UsernameNotOccupiedError, errors.UsernameInvalidError, ValueError):
        rep["notes"].append("[API] Username не найден или недоступен.")
    except errors.FloodWaitError as exc:
        rep["notes"].append(f"[API] Telegram попросил подождать {exc.seconds} с; остановите массовую проверку.")
    except Exception as exc:
        rep["notes"].append(f"[API] Ошибка: {exc}")


# Phone, username, domain, crypto --------------------------------------------
def scan_phone(target: str) -> dict:
    rep = new_report("Телефон", target)
    try:
        import phonenumbers
        from phonenumbers import PhoneNumberType as T, carrier, geocoder, timezone
    except ImportError:
        rep["notes"].append("Для разбора номеров установите: pip install phonenumbers")
        return rep
    raw = re.sub(r"[^\d+]", "", target)
    if not raw.startswith("+"):
        raw = "+" + raw
    try:
        number = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as exc:
        rep["notes"].append(f"Не удалось разобрать номер: {exc}")
        return rep
    valid = phonenumbers.is_valid_number(number)
    add(rep, "Международный формат", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    add(rep, "Валиден", "да" if valid else "нет")
    add(rep, "Страна/регион", geocoder.description_for_number(number, "ru"))
    add(rep, "Оператор по префиксу", carrier.name_for_number(number, "ru"))
    add(rep, "Часовые пояса", ", ".join(timezone.time_zones_for_number(number)))
    kind = phonenumbers.number_type(number)
    names = {T.MOBILE: "мобильный", T.FIXED_LINE: "стационарный", T.FIXED_LINE_OR_MOBILE: "моб./стационарный", T.VOIP: "VoIP", T.TOLL_FREE: "бесплатный", T.PREMIUM_RATE: "платный", T.UNKNOWN: "неизвестно"}
    add(rep, "Тип линии", names.get(kind, str(kind)))
    if not valid:
        flag(rep, 3, "Номер невалиден")
    if kind == T.VOIP:
        flag(rep, 3, "VoIP-номер; это сигнал для проверки, не доказательство мошенничества")
    if kind == T.PREMIUM_RATE:
        flag(rep, 3, "Платный номер")
    number_e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    digits = number_e164.lstrip("+")
    remember(rep, "phones", [target, number_e164, digits])
    rep["links"] += [("Google: номер + отзывы", f"https://www.google.com/search?q={quote(number_e164 + ' мошенник отзывы')}"), ("Яндекс: номер", f"https://yandex.ru/search/?text={quote(digits)}"), ("Telegram по номеру", f"https://t.me/+{digits}"), ("WhatsApp", f"https://wa.me/{digits}")]
    rep["notes"].append("По оператору и географии владельца установить нельзя; перенос номера может менять оператора.")
    return rep


def scan_email(target: str) -> dict:
    address = target.strip()
    rep = new_report("Email", address)
    remember(rep, "emails", address)
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    add(rep, "Домен", domain)
    rep["links"].append(("Google: email", f"https://www.google.com/search?q={quote(chr(34) + address + chr(34))}"))
    rep["notes"].append("Публичные совпадения email являются зацепками; утечки и закрытые базы Watson не запрашивает.")
    return rep


USER_SITES = {"GitHub": "https://github.com/{}", "GitLab": "https://gitlab.com/{}", "Keybase": "https://keybase.io/{}", "Medium": "https://medium.com/@{}", "Dev.to": "https://dev.to/{}", "Pastebin": "https://pastebin.com/u/{}", "Replit": "https://replit.com/@{}", "Behance": "https://www.behance.net/{}", "SoundCloud": "https://soundcloud.com/{}", "Telegram": "https://t.me/{}", "Habr": "https://habr.com/ru/users/{}/", "Pikabu": "https://pikabu.ru/@{}"}


def scan_username(target: str) -> dict:
    username = target.strip().lstrip("@")
    rep = new_report("Никнейм", username)
    remember(rep, "usernames", username)

    def check(item):
        name, template = item
        url = template.format(username)
        status, _ = fetch(url, timeout=8)
        return name, url, status

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(check, USER_SITES.items()))
    found = [(name, url) for name, url, status in results if status == 200]
    unsure = [name for name, _, status in results if status not in (200, 404)]
    add(rep, "Найден на", ", ".join(name for name, _ in found) or "нигде из проверенных")
    if unsure:
        add(rep, "Не удалось проверить", ", ".join(unsure))
    rep["links"] += found
    rep["notes"].append("Совпадение ника не означает, что это один человек.")
    if not found:
        flag(rep, 1, "Ник не найден на проверенных открытых площадках")
    return rep


def run_username_tool(rep: dict, tool: str, target: str) -> None:
    username = target.strip().lstrip("@")
    commands = {
        "Sherlock": ["sherlock", "--print-found", "--no-color", "--timeout", "15", username],
        "Maigret": ["maigret", username],
    }
    try:
        result = subprocess.run(commands[tool], capture_output=True, text=True, timeout=300, check=False)
    except FileNotFoundError:
        rep["notes"].append(f"{tool} не найден в PATH; установите его отдельно для этой проверки.")
        return
    except subprocess.TimeoutExpired:
        rep["notes"].append(f"{tool} не завершился за 300 с.")
        return
    output = result.stdout + "\n" + result.stderr
    urls = sorted({
        url.rstrip(".,;")
        for line in output.splitlines()
        if "[+]" in line or "CLAIMED" in line.upper()
        for url in re.findall(r"https?://[^\s<>\]\)]+", line)
    })
    if urls:
        add(rep, f"{tool}: найдено профилей", len(urls))
        rep["links"] += [(f"{tool}: найденный профиль", url) for url in urls]
    else:
        add(rep, f"{tool}: найдено профилей", "нет")
    if result.returncode and result.stderr.strip():
        rep["notes"].append(f"{tool}: {result.stderr.strip()[-500:]}")


def scan_domain(target: str) -> dict:
    domain = re.sub(r"^https?://", "", target.strip().lower()).split("/")[0].split(":")[0]
    rep = new_report("Домен", domain)
    remember(rep, "domains", domain)
    status, data = fetch_json(f"https://rdap.org/domain/{domain}")
    if isinstance(data, dict):
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                age = days_ago(event.get("eventDate"))
                add(rep, "Дата регистрации", event.get("eventDate", "")[:10])
                if age is not None and age < 180:
                    flag(rep, 4 if age < 30 else 2, f"Домен молодой ({age} дн.)")
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for item in entity.get("vcardArray", [None, []])[1]:
                    if item[0] == "fn":
                        add(rep, "Регистратор", item[3])
        add(rep, "NS", ", ".join(item.get("ldhName", "") for item in data.get("nameservers", [])))
        add(rep, "Статусы", ", ".join(data.get("status", [])))
    else:
        rep["notes"].append(f"RDAP недоступен (статус {status}); проверьте WHOIS вручную.")
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        add(rep, "IP", ", ".join(ips))
    except OSError:
        add(rep, "DNS", "домен не резолвится")
        flag(rep, 1, "Домен не резолвится")
    status, certs = fetch_json(f"https://crt.sh/?q={domain}&output=json", timeout=20)
    if isinstance(certs, list):
        names = {name for item in certs for name in item.get("name_value", "").split("\n")}
        add(rep, "Сертификатов crt.sh", len(certs))
        add(rep, "Поддомены (до 10)", ", ".join(sorted(name for name in names if name != domain)[:10]))
    rep["links"] += [("VirusTotal", f"https://www.virustotal.com/gui/domain/{domain}"), ("urlscan.io", f"https://urlscan.io/search/#domain:{domain}"), ("Wayback Machine", f"https://web.archive.org/web/*/{domain}"), ("WHOIS", f"https://who.is/whois/{domain}")]
    return rep


RE_BTC = re.compile(r"^(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
RE_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
RE_TRX = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


def crypto_kind(value: str) -> str | None:
    return "btc" if RE_BTC.fullmatch(value) else "eth" if RE_ETH.fullmatch(value) else "trx" if RE_TRX.fullmatch(value) else None


def scan_crypto(target: str) -> dict:
    address = target.strip()
    kind = crypto_kind(address)
    rep = new_report("Крипто-кошелёк", address)
    remember(rep, "crypto", address)
    if not kind:
        rep["notes"].append("Формат не похож на BTC / ETH / TRON адрес.")
        return rep
    add(rep, "Сеть по формату", {"btc": "Bitcoin", "eth": "Ethereum/EVM", "trx": "TRON"}[kind])
    explorer = {"btc": f"https://www.blockchain.com/explorer/addresses/btc/{address}", "eth": f"https://etherscan.io/address/{address}", "trx": f"https://tronscan.org/#/address/{address}"}[kind]
    rep["links"] += [("Обозреватель", explorer), ("Chainabuse", f"https://www.chainabuse.com/address/{address}")]
    rep["notes"].append("Проверьте публичные транзакции и жалобы вручную; связь кошелька с человеком не устанавливается этим скриптом.")
    if kind in ("btc", "eth"):
        chain, key = ("bitcoin", address) if kind == "btc" else ("ethereum", address.lower())
        status, data = fetch_json(f"https://api.blockchair.com/{chain}/dashboards/address/{address}")
        info = (data or {}).get("data", {}).get(key, {}).get("address") if isinstance(data, dict) else None
        if info:
            divisor, symbol = (1e8, "BTC") if kind == "btc" else (1e18, "ETH")
            add(rep, "Баланс", f"{float(info.get('balance', 0)) / divisor:.6f} {symbol}")
            add(rep, "Транзакций", info.get("transaction_count"))
        else:
            rep["notes"].append(f"Blockchair не вернул данные (статус {status}).")
    else:
        status, data = fetch_json(f"https://apilist.tronscanapi.com/api/accountv2?address={address}")
        if isinstance(data, dict):
            add(rep, "Баланс TRX", f"{float(data.get('balance', 0)) / 1e6:.2f}")
            add(rep, "Транзакций", data.get("totalTransactionCount"))
        else:
            rep["notes"].append(f"Tronscan не вернул данные (статус {status}).")
    return rep


# Output and CLI --------------------------------------------------------------
def detect(value: str) -> str:
    target = value.strip()
    path = Path(target).expanduser()
    if path.is_file() and path.suffix.lower() == ".json":
        return "export"
    if target.startswith("@") or re.search(r"(t\.me|telegram\.me)/", target):
        return "tg"
    if crypto_kind(target):
        return "crypto"
    if EMAIL_RE.fullmatch(target):
        return "email"
    if re.fullmatch(r"\+?[\d\s\-()]{9,18}", target):
        return "phone"
    if re.search(r"^(https?://)?[\w.-]+\.[a-z]{2,}(/.*)?$", target, re.I):
        return "domain"
    return "user"


SCANNERS = {"tg": scan_telegram, "id": scan_id, "phone": scan_phone, "email": scan_email, "user": scan_username, "domain": scan_domain, "crypto": scan_crypto, "export": scan_export, "evidence": scan_evidence}


def run(kind: str, target: str, deep: bool = False, sherlock: bool = False, maigret: bool = False) -> dict:
    rep = SCANNERS[kind](target)
    if kind in ("tg", "id") and deep:
        deep_telegram(rep, telegram_slug(target))
    if kind in ("tg", "user") and (sherlock or maigret):
        username = telegram_slug(target) if kind == "tg" else target
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", username):
            rep["notes"].append("Sherlock/Maigret требуют username, а не Telegram ID или ссылку.")
        else:
            if sherlock:
                run_username_tool(rep, "Sherlock", username)
            if maigret:
                run_username_tool(rep, "Maigret", username)
    return rep


def correlate_reports(reports: list[dict]) -> None:
    matches = {}
    for index, rep in enumerate(reports):
        for kind, values in rep.get("indicators", {}).items():
            for value in values:
                normalized = str(value).strip()
                if kind in ("usernames", "emails", "domains"):
                    normalized = normalized.lower()
                elif kind == "phones":
                    normalized = re.sub(r"\D", "", normalized)
                if kind == "usernames":
                    normalized = normalized.lstrip("@")
                matches.setdefault((kind, normalized), {})[index] = value
    for (kind, normalized), occurrences in matches.items():
        if len(occurrences) < 2 or not normalized:
            continue
        display = next(iter(occurrences.values()))
        related = ", ".join(reports[index]["target"] for index in occurrences)
        for index in occurrences:
            add(reports[index], "Корреляция индикатора", f"{kind}: {display} → {related}")


def read_targets(path: str) -> list[tuple[str, str]]:
    targets = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if parts[0] in SCANNERS and len(parts) > 1:
            targets.append((parts[0], parts[1]))
        else:
            targets.append((detect(line), line))
    return targets


def print_report(rep: dict) -> None:
    score, level = risk(rep)
    print(f"\n=== {rep['type']}: {rep['target']} ===")
    for label, value in rep["findings"]:
        print(f"  {label}: {value}")
    print(f"\n  Оценка риска: {level} ({score})")
    for points, reason in rep["flags"]:
        if reason:
            print(f"   [+{points}] {reason}")
    for note in rep["notes"]:
        print(f"  * {note}")
    for name, url in rep["links"]:
        print(f"  -> {name}: {url}")
    print("\n  Оценка эвристическая. Не публикуйте персональные данные.")


def html_report(rep: dict) -> str:
    score, level = risk(rep)
    escape = html.escape
    rows = "".join(f"<tr><th>{escape(str(label))}</th><td>{escape(str(value))}</td></tr>" for label, value in rep["findings"])
    flags = "".join(f"<li>+{points}: {escape(reason)}</li>" for points, reason in rep["flags"] if reason) or "<li>признаков не найдено</li>"
    notes = "".join(f"<li>{escape(note)}</li>" for note in rep["notes"])
    links = "".join(f'<li><a href="{escape(url)}" rel="noopener noreferrer">{escape(name)}</a></li>' for name, url in rep["links"])
    colors = {"низкий": "#2e7d32", "средний": "#ef6c00", "высокий": "#c62828"}
    return f'<section class="card"><h2>{escape(rep["type"])}: {escape(rep["target"])}</h2><p class="risk" style="background:{colors[level]}">Риск: {level} ({score})</p><table>{rows}</table><h3>Признаки</h3><ul>{flags}</ul><h3>Заметки</h3><ul>{notes}</ul><h3>Ссылки для ручной проверки</h3><ul>{links}</ul></section>'


def render_page(reports: list[dict]) -> str:
    body = "".join(html_report(rep) for rep in reports)
    return f"<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Watson report</title><style>body{{max-width:820px;margin:2rem auto;padding:0 1rem;font-family:system-ui,sans-serif}}.card{{border:1px solid #8884;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}}.risk{{display:inline-block;color:#fff;padding:.2rem .7rem;border-radius:6px}}table{{border-collapse:collapse;width:100%}}th{{text-align:left;width:34%;vertical-align:top;padding:.2rem}}td{{padding:.2rem;word-break:break-word}}</style></head><body><h1>Watson</h1><small>Сформирован {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}. Оценка эвристическая.</small>{body}</body></html>"


def save_pdf(page: str, path: str) -> None:
    try:
        from weasyprint import HTML
    except ImportError:
        print("Для PDF: pip install weasyprint; либо откройте HTML и выберите 'Печать → PDF'.")
        return
    HTML(string=page).write_pdf(path)
    print(f"PDF сохранён: {path}")


def save_csv(reports: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as output:
        writer = csv.writer(output)
        writer.writerow(["тип", "цель", "риск", "баллы", "признаки"])
        for rep in reports:
            score, level = risk(rep)
            writer.writerow([rep["type"], rep["target"], level, score, " | ".join(reason for _, reason in rep["flags"])])
    print(f"CSV сохранён: {path}")


def markdown_report(reports: list[dict]) -> str:
    lines = ["# Watson report", ""]
    for rep in reports:
        score, level = risk(rep)
        lines += [f"## {rep['type']}: {rep['target']}", "", f"- Риск: **{level} ({score})**", ""]
        if rep["findings"]:
            lines += ["### Данные", ""]
            lines += [f"- **{label}:** {value}" for label, value in rep["findings"]]
            lines.append("")
        if rep["flags"]:
            lines += ["### Признаки", ""]
            lines += [f"- +{points}: {reason}" for points, reason in rep["flags"] if reason]
            lines.append("")
        if rep["notes"]:
            lines += ["### Заметки", ""]
            lines += [f"- {note}" for note in rep["notes"]]
            lines.append("")
    return "\n".join(lines)


def self_test() -> None:
    messages = [{"id": 1, "text": "Срочно оплатите комиссию: https://example.test @helper"}]
    rep = scan_export_from_messages(messages)
    assert risk(rep)[0] == 6
    assert detect("+79991234567") == "phone"
    assert crypto_kind("0x0000000000000000000000000000000000000000") == "eth"
    assert "Примерная дата регистрации" in dict(scan_id("1973230366")["findings"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Watson — OSINT-триаж по открытым источникам и собственным экспортам")
    parser.add_argument("args", nargs="*", help="цель или: тип цель (tg|id|phone|email|user|domain|crypto|export|evidence)")
    parser.add_argument("-f", "--file", help="файл целей, по одной в строке")
    parser.add_argument("--export", help="Telegram Desktop JSON-экспорт")
    parser.add_argument("--evidence", action="append", metavar="PATH", help="локальный JSON/CSV/TXT-материал расследования; можно указать несколько раз")
    parser.add_argument("--id", dest="telegram_id", help="проверить Telegram ID и оценить дату регистрации")
    parser.add_argument("--out", help="сохранить Markdown-отчёт")
    parser.add_argument("--deep", action="store_true", help="дополнительные данные Telegram через ваш Telethon-сеанс")
    parser.add_argument("--sherlock", action="store_true", help="проверить username через установленный Sherlock")
    parser.add_argument("--maigret", action="store_true", help="проверить username через установленный Maigret")
    parser.add_argument("--html", help="сохранить HTML")
    parser.add_argument("--pdf", help="сохранить PDF через weasyprint")
    parser.add_argument("--json", help="сохранить JSON")
    parser.add_argument("--csv", help="сохранить CSV")
    parser.add_argument("--no-cache", action="store_true", help="удалить локальный HTTP-кэш перед запуском")
    parser.add_argument("--self-test", action="store_true", help="запустить встроенную проверку")
    ns = parser.parse_args(argv)
    if ns.self_test:
        self_test()
        print("ok")
        return 0
    if ns.no_cache and CACHE_DB.exists():
        CACHE_DB.unlink()

    targets = read_targets(ns.file) if ns.file else []
    if ns.export:
        targets.append(("export", ns.export))
    for path in ns.evidence or []:
        targets.append(("evidence", path))
    if ns.telegram_id:
        targets.append(("id", ns.telegram_id))
    if ns.args:
        if ns.args[0] in SCANNERS and len(ns.args) > 1:
            targets.append((ns.args[0], " ".join(ns.args[1:])))
        else:
            value = " ".join(ns.args)
            targets.append((detect(value), value))
    if not targets:
        parser.error("укажите цель, --export или --file")

    reports = []
    for index, (kind, target) in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"[{index}/{len(targets)}] {kind}: {target}", file=sys.stderr)
        try:
            reports.append(run(kind, target, ns.deep, ns.sherlock, ns.maigret))
        except (OSError, ValueError) as exc:
            print(f"ошибка {target}: {exc}", file=sys.stderr)
        if index < len(targets):
            time.sleep(2.0 if ns.deep else 0.5)
    correlate_reports(reports)
    reports.sort(key=lambda rep: risk(rep)[0], reverse=True)
    for rep in reports:
        print_report(rep)
    if len(reports) > 1:
        print("\n=== Сводка ===")
        for rep in reports:
            score, level = risk(rep)
            print(f"  {level:8} ({score:2})  {rep['type']}: {rep['target']}")

    page = render_page(reports)
    if ns.html:
        Path(ns.html).write_text(page, encoding="utf-8")
        print(f"HTML сохранён: {ns.html}")
    if ns.pdf:
        save_pdf(page, ns.pdf)
    if ns.json:
        Path(ns.json).write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON сохранён: {ns.json}")
    if ns.csv:
        save_csv(reports, ns.csv)
    if ns.out:
        Path(ns.out).write_text(markdown_report(reports), encoding="utf-8")
        print(f"Markdown сохранён: {ns.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
