#!/usr/bin/env python3
"""Watson: evidence-first OSINT triage for scam reports.

Public web checks, breach-exposure status (names, dates and data classes
only) and Telegram data visible to the authenticated user are summarised as
leads, never as proof of identity. Raw breach dumps and private databases are
not fetched; locally supplied investigation evidence may be processed and
correlated.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

try:
    import curses
except ImportError:  # платформы без curses (обычно Windows)
    curses = None


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


def fetch(url: str, ttl: int = CACHE_TTL, timeout: int = 12, headers: dict | None = None) -> tuple[int, str]:
    """Cached GET using only the standard library."""
    con = cache_db()
    row = con.execute("SELECT status, body, ts FROM c WHERE url=?", (url,)).fetchone()
    if row and time.time() - row[2] < ttl:
        con.close()
        return row[0], row[1]
    try:
        request = Request(url, headers={**UA, **(headers or {})})
        with urlopen(request, timeout=timeout) as response:
            status, body = response.status, response.read().decode("utf-8", "replace")
    except HTTPError as exc:
        con.close()
        return exc.code, ""
    except (URLError, TimeoutError, OSError):
        con.close()
        return 0, ""
    if status < 500 and status not in (403, 429):
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
    rep["links"] += [("Профиль t.me", f"https://t.me/{username}"), ("Поиск ника в Google", f"https://www.google.com/search?q={quote(chr(34) + username + chr(34))}"), ("Поиск ника в Яндексе", f"https://yandex.ru/search/?text={quote(chr(34) + username + chr(34))}")] + username_dork_links(username)
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


def phone_social_links(digits: str, number_e164: str | None = None) -> list[tuple[str, str]]:
    """Публичные ссылки для ручной OSINT-проверки номера (без обращения к закрытым базам)."""
    e164 = number_e164 or ("+" + digits)
    exact = quote(chr(34) + digits + chr(34))
    return [
        ("Google: номер + отзывы", f"https://www.google.com/search?q={quote(e164 + ' мошенник отзывы')}"),
        ("Google: точное совпадение номера", f"https://www.google.com/search?q={exact}"),
        ("Яндекс: номер", f"https://yandex.ru/search/?text={quote(digits)}"),
        ("Google dork: VK / OK / Instagram", f"https://www.google.com/search?q={quote(chr(34) + digits + chr(34) + ' site:vk.com OR site:ok.ru OR site:instagram.com OR site:tiktok.com OR site:facebook.com OR site:avito.ru')}"),
        ("Telegram по номеру", f"https://t.me/+{digits}"),
        ("WhatsApp", f"https://wa.me/{digits}"),
        ("Viber", f"viber://add?number={digits}"),
        ("Truecaller: публичный поиск", f"https://www.truecaller.com/search/ru/{digits}"),
        ("VK: поиск (через Google)", f"https://www.google.com/search?q={quote(chr(34) + digits + chr(34) + ' site:vk.com')}"),
        ("OK.ru: поиск (через Google)", f"https://www.google.com/search?q={quote(chr(34) + digits + chr(34) + ' site:ok.ru')}"),
        ("Avito: поиск (через Google)", f"https://www.google.com/search?q={quote(chr(34) + digits + chr(34) + ' site:avito.ru')}"),
        ("DuckDuckGo: номер", f"https://duckduckgo.com/?q={quote(chr(34) + digits + chr(34))}"),
    ]


def email_social_links(address: str) -> list[tuple[str, str]]:
    local, _, domain = address.partition("@")
    gravatar = hashlib.md5(address.strip().lower().encode()).hexdigest()
    exact = quote(chr(34) + address + chr(34))
    return [
        ("Google: точное совпадение email", f"https://www.google.com/search?q={exact}"),
        ("Google: email + соцсети", f"https://www.google.com/search?q={quote(chr(34) + address + chr(34) + ' site:github.com OR site:gitlab.com OR site:linkedin.com OR site:x.com OR site:reddit.com OR site:telegram.org')}"),
        ("Яндекс: email", f"https://yandex.ru/search/?text={quote(address)}"),
        ("Gravatar: профиль по hash", f"https://www.gravatar.com/avatar/{gravatar}"),
        ("Gravatar: публичный профиль", f"https://www.gravatar.com/{gravatar}"),
        ("GitHub: поиск пользователя", f"https://github.com/search?q={quote(address)}&type=users"),
        ("Hunter: домен", f"https://hunter.io/search/{domain}") if domain else ("Hunter", "https://hunter.io/"),
    ]


def username_dork_links(username: str) -> list[tuple[str, str]]:
    exact = quote(chr(34) + username + chr(34))
    return [
        ("Google: точное совпадение ника", f"https://www.google.com/search?q={exact}"),
        ("Google: ник + соцсети", f"https://www.google.com/search?q={quote(chr(34) + username + chr(34) + ' site:vk.com OR site:ok.ru OR site:instagram.com OR site:tiktok.com OR site:telegram.org')}"),
        ("Яндекс: ник", f"https://yandex.ru/search/?text={quote(chr(34) + username + chr(34))}"),
        ("Bing: ник", f"https://www.bing.com/search?q={exact}"),
    ]


def image_reverse_links(target: str) -> list[tuple[str, str]]:
    value = target.strip()
    links = []
    if re.match(r"^https?://", value, re.I):
        encoded = quote(value, safe="")
        links.append(("Google Lens: изображение", f"https://lens.google.com/uploadbyurl?url={encoded}"))
        links.append(("Yandex Images: обратный поиск", f"https://yandex.ru/images/search?rpt=imageview&url={encoded}"))
        links.append(("TinEye: обратный поиск", f"https://tineye.com/search?url={encoded}"))
    links.append(("Google Images", "https://images.google.com/"))
    links.append(("Yandex Images", "https://yandex.ru/images/"))
    links.append(("PimEyes: поиск лица", "https://pimeyes.com/en"))
    links.append(("Social Catfish: обратный поиск фото", "https://socialcatfish.com/reverse-image-search/"))
    return links


def osint_pivot_links(kind: str, target: str, indicators: dict | None = None) -> list[tuple[str, str]]:
    """Дополнительные ручные точки OSINT, как у ботов-агрегаторов открытых данных."""
    result: list[tuple[str, str]] = []
    if kind == "phone":
        number = re.sub(r"\D", "", target)
        result += phone_social_links(number)
    elif kind in ("email", "Email"):
        result += email_social_links(target)
    elif kind in ("username", "Никнейм", "tg"):
        slug = telegram_slug(target)
        if slug:
            result += username_dork_links(slug)
    elif kind == "domain":
        result += [
            ("Google: домен + соцсети", f"https://www.google.com/search?q={quote(chr(34) + target + chr(34) + ' scam OR мошенник OR отзывы')}"),
            ("Wayback Machine", f"https://web.archive.org/web/*/{target}"),
        ]
    elif kind in ("crypto", "Крипто-кошелёк"):
        result += [
            ("Breadcrumbs", f"https://breadcrumbs.app/"),
            ("Chainabuse", f"https://www.chainabuse.com/address/{target}"),
        ]
    return result


# Phone, username, domain, crypto --------------------------------------------
def scan_phone(target: str) -> dict:
    rep = new_report("Телефон", target)
    try:
        import phonenumbers
        from phonenumbers import PhoneNumberType as T, carrier, geocoder, timezone
    except ImportError:
        digits = re.sub(r"\D", "", target)
        if digits:
            add(rep, "Цифры номера", digits)
            rep["links"] += phone_social_links(digits)
        rep["notes"].append("Для разбора номеров установите: pip install phonenumbers")
        rep["notes"].append("Без библиотеки доступна только базовая OSINT-навигация; формат, регион и оператор не определены.")
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
    rep["links"] += phone_social_links(digits, number_e164)
    rep["notes"].append("По оператору и географии владельца установить нельзя; перенос номера может менять оператора.")
    rep["notes"].append("Связи номера с аккаунтами соцсетей являются зацепками; нужны независимая проверка и согласие на обработку персональных данных, если речь идёт о реальном человеке.")
    return rep


def scan_email(target: str) -> dict:
    address = target.strip()
    rep = new_report("Email", address)
    remember(rep, "emails", address)
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    add(rep, "Домен", domain)
    rep["links"] += email_social_links(address)
    rep["notes"].append("Публичные совпадения email являются зацепками; сырые дампы и закрытые базы Watson не запрашивает.")
    return rep


# Email investigation (MailAccess-compatible) ---------------------------------
# MailAccess is an optional external engine: https://github.com/KatrielMoses/MailAccess
# When it is installed, Watson runs its "investigate" command and folds the
# graded findings into a normal Watson report. Without it, Watson falls back to
# a small built-in set of public, logged-out checks.

MAILACCESS_TIMEOUT = 600
MAILACCESS_ACCOUNT_MODULES = {
    "account_discovery",
    "browser_account_probe",
    "breach_deep",
    "fediverse_discovery",
    "github_code_search",
    "github_commits",
    "google_account_intel",
    "gravatar",
    "gravatar_lookup",
    "hackernews",
    "keybase",
    "messaging_hints",
    "npm_discovery",
    "orcid_lookup",
    "outlook_autodiscover",
    "pgp_keyserver",
    "phone_intel",
    "pypi_discovery",
    "social",
    "social_discovery",
    "social_links",
    "username_platforms",
    "username_pivot",
}
CONFIDENCE_RU = {
    "confirmed": "подтверждено",
    "high": "высокая",
    "likely": "вероятно",
    "medium": "средняя",
    "possible": "возможно",
    "low": "низкая",
    "username match": "совпадение ника",
    "unknown": "неизвестно",
}
CONFIDENCE_RANK = {"confirmed": 0, "high": 1, "likely": 2, "medium": 3, "possible": 4, "low": 5, "username match": 6}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def mailaccess_binary() -> str | None:
    override = os.getenv("WATSON_MAILACCESS_BIN", "").strip()
    if override:
        path = Path(override).expanduser()
        if path.is_file():
            return str(path)
        return shutil.which(override)
    return shutil.which("mailaccess")


def _mailaccess_payload(stdout: str) -> dict:
    """Extract the JSON object from MailAccess stdout, tolerating stray lines."""
    text = stdout.strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("в выводе нет JSON-объекта")
    data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("JSON-ответ не является объектом")
    return data


def run_mailaccess(address: str) -> tuple[dict | None, str]:
    """Run `mailaccess investigate` and return its report, or (None, reason)."""
    binary = mailaccess_binary()
    if not binary:
        return None, "не установлен"
    command = [binary, "--local-only", "--no-banner", "investigate", address, "--format", "json"]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=MAILACCESS_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return None, f"не завершился за {MAILACCESS_TIMEOUT} с"
    except OSError as exc:
        return None, str(exc)
    # MailAccess returns 0 for a completed run, 1 when the run failed but a
    # report object is still available, and 2 for active breaches in some
    # versions; all three carry parseable JSON.
    if proc.returncode not in (0, 1, 2):
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        suffix = f": {detail[-1][:300]}" if detail else ""
        return None, f"код {proc.returncode}{suffix}"
    try:
        return _mailaccess_payload(proc.stdout), ""
    except (TypeError, ValueError) as exc:
        return None, f"не удалось разобрать JSON ({exc})"


def _mailaccess_items(data: dict) -> list[tuple[str, dict]]:
    items: list[tuple[str, dict]] = []
    by_module = data.get("findings_by_module")
    if isinstance(by_module, dict) and by_module:
        for module, findings in by_module.items():
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if isinstance(finding, dict):
                    items.append((str(module), finding))
    else:
        for finding in data.get("findings") or []:
            if isinstance(finding, dict):
                items.append((str(finding.get("module") or "findings"), finding))
    return items


def _finding_platform(module: str, finding: dict) -> str:
    return str(
        finding.get("platform")
        or finding.get("service")
        or finding.get("source")
        or finding.get("site")
        or module
    ).strip()


def _finding_url(finding: dict) -> str:
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    url = str(
        finding.get("url")
        or finding.get("profile_url")
        or finding.get("link")
        or metadata.get("profile_url")
        or metadata.get("url")
        or ""
    ).strip()
    return url if url.lower().startswith(("http://", "https://")) else ""


def _finding_names(finding: dict) -> list[str]:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        return []
    names = []
    for key in ("display_name", "full_name", "name", "username", "login", "handle"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            names.append(value.strip())
    return names


def apply_mailaccess_report(rep: dict, data: dict) -> None:
    """Fold a MailAccess report into Watson's finding/link layout."""
    status = str(data.get("status") or "").lower()
    add(rep, "MailAccess: статус", data.get("status"))
    if status == "failed":
        rep["notes"].append("MailAccess сообщил о неудачном прогоне: результаты неполные.")
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    score = data.get("exposure_score", summary.get("exposure_score"))
    add(rep, "MailAccess: exposure score", score)
    add(rep, "MailAccess: уровень риска", data.get("risk_level", summary.get("risk_level")))
    add(rep, "MailAccess: email после нормализации", data.get("canonical_email"))

    items = _mailaccess_items(data)
    add(rep, "MailAccess: всего находок", len(items))
    counts: dict[str, int] = {}
    for module, _ in items:
        counts[module] = counts.get(module, 0) + 1
    if counts:
        ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        shown = ", ".join(f"{module} ({count})" for module, count in ordered[:12])
        if len(ordered) > 12:
            shown += f" и ещё {len(ordered) - 12} модулей"
        add(rep, "MailAccess: модули с находками", shown)

    details = [
        (module, finding)
        for module, finding in items
        if module in MAILACCESS_ACCOUNT_MODULES
    ]
    details.sort(
        key=lambda item: (
            CONFIDENCE_RANK.get(str(item[1].get("confidence", "unknown")).lower(), 9),
            SEVERITY_RANK.get(str(item[1].get("severity", "info")).lower(), 9),
        )
    )
    seen: set[tuple[str, str]] = set()
    names: list[str] = []
    for module, finding in details:
        platform = _finding_platform(module, finding)
        url = _finding_url(finding)
        key = (platform, url)
        if key in seen:
            continue
        seen.add(key)
        confidence = str(finding.get("confidence") or "").lower()
        grade = CONFIDENCE_RU.get(confidence, confidence)
        label = f"MailAccess: аккаунт {platform}" + (f" ({grade})" if grade else "")
        if len(seen) <= 30:
            add(rep, label, url or "найден")
        if url:
            rep["links"].append((f"MailAccess: {platform}", url))
        for name in _finding_names(finding):
            if name not in names:
                names.append(name)
    for name in names[:3]:
        add(rep, "MailAccess: возможное имя/логин", name)

    if len(seen) > 30:
        add(rep, "MailAccess: аккаунтов показано", f"30 из {len(seen)}; полный список — в отчёте MailAccess")
    if items:
        rep["notes"].append("MailAccess проверяет публичные страницы регистрации/входа; оценка уверенности — его эвристика, а не доказательство владения адресом.")
    else:
        rep["notes"].append("MailAccess не вернул находок: это не подтверждает отсутствие аккаунтов.")


def builtin_email_accounts(rep: dict, address: str) -> None:
    """Small public fallback when the MailAccess CLI is not installed."""
    digest = hashlib.md5(address.strip().lower().encode()).hexdigest()

    status, data = fetch_json(f"https://www.gravatar.com/{digest}.json", timeout=10)
    profile = None
    if isinstance(data, dict):
        entry = data.get("entry")
        if isinstance(entry, list) and entry and isinstance(entry[0], dict):
            profile = entry[0]
        elif data.get("displayName") or data.get("preferredUsername"):
            profile = data
    if profile:
        name = str(profile.get("displayName") or profile.get("preferredUsername") or "").strip()
        add(rep, "Gravatar: профиль", name or "найден")
        rep["links"].append(("Gravatar: профиль", f"https://gravatar.com/{digest}"))
        accounts = profile.get("accounts")
        if isinstance(accounts, list) and accounts:
            add(rep, "Gravatar: привязанные аккаунты", len(accounts))

    status, data = fetch_json(
        "https://keybase.io/_/api/1.0/user/lookup.json?email=" + quote(address),
        timeout=10,
    )
    if isinstance(data, dict):
        status_obj = data.get("status") if isinstance(data.get("status"), dict) else {}
        if status_obj.get("code") == 0:
            them = data.get("them")
            users = them if isinstance(them, list) else [them] if isinstance(them, dict) else []
            for user in users:
                basics = user.get("basics") if isinstance(user, dict) else None
                if not isinstance(basics, dict) or not basics.get("username"):
                    continue
                username = str(basics["username"])
                add(rep, "Keybase: аккаунт", username)
                rep["links"].append(("Keybase: профиль", f"https://keybase.io/{quote(username)}"))

    status, data = fetch_json(
        "https://api.github.com/search/users?q=" + quote(address) + "+in:email",
        timeout=10,
        headers={"Accept": "application/vnd.github+json"},
    )
    if isinstance(data, dict):
        found = data.get("items") if isinstance(data.get("items"), list) else []
        for item in found[:5]:
            if not isinstance(item, dict) or not item.get("login"):
                continue
            login = str(item["login"])
            add(rep, "GitHub: аккаунт", login)
            url = str(item.get("html_url") or f"https://github.com/{quote(login)}")
            rep["links"].append(("GitHub: профиль", url))
        total = data.get("total_count")
        if isinstance(total, int) and total > 5:
            add(rep, "GitHub: всего совпадений", total)
    elif status in (403, 429):
        rep["notes"].append("GitHub: лимит публичного поиска исчерпан, повторите позже.")

    status, body = fetch("https://keys.openpgp.org/vks/v1/by-email/" + quote(address), timeout=10)
    if status == 200 and body.strip():
        add(rep, "OpenPGP: ключ", "найден")
        rep["links"].append(("OpenPGP: ключ", "https://keys.openpgp.org/search?q=" + quote(address)))


def scan_mailaccess(target: str) -> dict:
    address = target.strip()
    rep = new_report("Email-расследование (MailAccess)", address)
    remember(rep, "emails", address)
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    add(rep, "Домен", domain)
    rep["links"] += email_social_links(address)

    data, error = run_mailaccess(address)
    if data:
        add(rep, "MailAccess: движок", "MailAccess CLI")
        apply_mailaccess_report(rep, data)
    else:
        add(rep, "MailAccess: движок", "встроенная проверка")
        if error and error != "не установлен":
            rep["notes"].append(f"MailAccess: {error}.")
        rep["notes"].append(
            "Полный прогон MailAccess: pip install mailaccess. "
            "Сейчас выполнены встроенные публичные проверки Gravatar, Keybase, GitHub и OpenPGP."
        )
        builtin_email_accounts(rep, address)

    rep["notes"].append("Аккаунт, найденный по email, — зацепка для проверки, а не доказательство владения адресом.")
    return rep



USER_SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Keybase": "https://keybase.io/{}",
    "Medium": "https://medium.com/@{}",
    "Dev.to": "https://dev.to/{}",
    "Pastebin": "https://pastebin.com/u/{}",
    "Replit": "https://replit.com/@{}",
    "Behance": "https://www.behance.net/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Telegram": "https://t.me/{}",
    "Habr": "https://habr.com/ru/users/{}/",
    "Pikabu": "https://pikabu.ru/@{}",
    "Reddit": "https://www.reddit.com/user/{}/",
    "X (Twitter)": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Facebook": "https://www.facebook.com/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "VK": "https://vk.com/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Steam": "https://steamcommunity.com/id/{}",
}


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
    rep["links"] += username_dork_links(username)
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
    status, otx = fetch_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general", timeout=20)
    if isinstance(otx, dict):
        pulses = int(((otx.get("pulse_info") or {}).get("count")) or 0)
        add(rep, "AlienVault OTX: упоминаний в threat-пульсах", pulses)
        whitelisted = any(
            "whitelist" in (str(item.get("name", "")) + str(item.get("message", ""))).lower()
            for item in otx.get("validation") or []
            if isinstance(item, dict)
        )
        if whitelisted:
            rep["notes"].append("OTX помечает домен как whitelisted; упоминания в пульсах не учитывались в оценке риска.")
        elif pulses >= 5:
            flag(rep, 3, f"Домен встречается в {pulses} публичных threat-пульсах OTX")
        elif pulses:
            flag(rep, 1, f"Домен встречается в {pulses} threat-пульсах OTX")
    else:
        rep["notes"].append(f"AlienVault OTX недоступен (статус {status}).")
    status, scan = fetch_json("https://urlscan.io/api/v1/search/?q=" + quote(f"domain:{domain}"), timeout=20)
    if isinstance(scan, dict):
        scanned = int(scan.get("total") or 0)
        add(rep, "urlscan.io: публичных сканов", scanned)
        if scanned:
            rep["notes"].append("Наличие сканов urlscan.io означает, что домен уже проверяли другие исследователи.")
    else:
        rep["notes"].append(f"urlscan.io недоступен (статус {status}).")
    rep["links"] += [("VirusTotal", f"https://www.virustotal.com/gui/domain/{domain}"), ("urlscan.io", f"https://urlscan.io/search/#domain:{domain}"), ("AlienVault OTX", f"https://otx.alienvault.com/indicator/domain/{domain}"), ("Wayback Machine", f"https://web.archive.org/web/*/{domain}"), ("WHOIS", f"https://who.is/whois/{domain}")]
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


def scan_image(target: str) -> dict:
    value = target.strip()
    rep = new_report("Изображение / обратный поиск лица", value)
    local = Path(value).expanduser()
    if local.exists() and local.is_file():
        add(rep, "Локальный файл", local.name)
        try:
            add(rep, "Размер файла", local.stat().st_size)
            add(rep, "SHA-256", hashlib.sha256(local.read_bytes()).hexdigest())
        except (OSError, ValueError) as exc:
            rep["notes"].append(f"Не удалось прочитать файл: {exc}")
    rep["links"] += image_reverse_links(value)
    rep["notes"].append("Watson не выполняет распознавание лиц локально; отчёты по фото проверяются вручную через обратный поиск и сервисы facial recognition.")
    rep["notes"].append("Загрузка изображения в сторонние сервисы может раскрывать биометрические данные; делайте это только по законному основанию.")
    remember(rep, "images", value)
    return rep


# Breach exposure status: names, dates and data classes only, never the values
_BREACH_LAST: dict[str, float] = {}


def throttle(key: str, interval: float) -> None:
    wait = interval - (time.time() - _BREACH_LAST.get(key, 0.0))
    if wait > 0:
        time.sleep(wait)
    _BREACH_LAST[key] = time.time()


def breach_kind(identifier: str) -> str:
    value = str(identifier).strip()
    if EMAIL_RE.fullmatch(value):
        return "email"
    if re.fullmatch(r"\+?\d[\d\s().-]{6,20}\d", value):
        return "phone"
    return "username"


def leakcheck_public(query: str) -> dict:
    result = {"source": "LeakCheck", "count": None, "breaches": [], "fields": [], "error": ""}
    throttle("leakcheck", 1.1)
    status, data = fetch_json(f"https://leakcheck.io/api/public?check={quote(query)}", ttl=3600, timeout=20)
    if status == 429:
        result["error"] = "rate limit, повторите позже"
        return result
    if not isinstance(data, dict):
        result["error"] = f"HTTP {status}"
        return result
    if not data.get("success"):
        result["error"] = str(data.get("message") or data.get("error") or "нет ответа")
        return result
    result["count"] = int(data.get("found") or 0)
    result["breaches"] = [
        f"{item.get('name', '?')} ({item.get('date', 'дата н/д')})"
        for item in data.get("sources") or []
        if isinstance(item, dict)
    ]
    result["fields"] = [str(field) for field in data.get("fields") or []]
    return result


def leakcheck_pro(query: str, kind: str | None = None) -> dict:
    if kind == "phone":
        query = re.sub(r"\D", "", query)
    result = {"source": "LeakCheck Pro", "count": None, "breaches": [], "fields": [], "error": ""}
    key = os.getenv("WATSON_LEAKCHECK_KEY")
    if not key:
        return result
    throttle("leakcheck", 1.1)
    query_url = f"https://leakcheck.io/api/v2/query/{quote(query)}?limit=100"
    if kind in ("phone",):
        query_url += "&type=phone"
    elif kind in ("email",):
        query_url += "&type=email"
    elif kind in ("username",):
        query_url += "&type=username"
    status, data = fetch_json(
        query_url,
        ttl=3600, timeout=20, headers={"X-API-Key": key, "Accept": "application/json"},
    )
    if status == 401:
        result["error"] = "неверный WATSON_LEAKCHECK_KEY"
        return result
    if status == 429:
        result["error"] = "rate limit, повторите позже"
        return result
    if not isinstance(data, dict):
        result["error"] = f"HTTP {status}"
        return result
    if not data.get("success"):
        result["error"] = str(data.get("message") or data.get("error") or "нет ответа")
        return result
    result["count"] = int(data.get("found") or 0)
    breaches: set[str] = set()
    fields: set[str] = set()
    for row in data.get("result") or []:
        if not isinstance(row, dict):
            continue
        source = row.get("source") if isinstance(row.get("source"), dict) else {}
        name = str(source.get("name") or "?")
        date = str(source.get("breach_date") or "")[:7]
        breaches.add(f"{name} ({date})" if date else name)
        fields.update(str(field) for field in row.get("fields") or [])
    result["breaches"] = sorted(breaches)
    result["fields"] = sorted(fields)
    result["quota"] = data.get("quota")
    return result


def xposedornot_breaches(email: str) -> dict:
    result = {"source": "XposedOrNot", "count": None, "breaches": [], "fields": [], "error": ""}
    throttle("xposedornot", 0.6)
    status, data = fetch_json(
        "https://api.xposedornot.com/v1/breach-analytics?email=" + quote(email),
        ttl=3600, timeout=25,
    )
    if status == 429:
        result["error"] = "rate limit (25 запросов/час), повторите позже"
        return result
    if not isinstance(data, dict):
        result["error"] = f"HTTP {status}"
        return result
    details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
    fields: set[str] = set()
    for item in details:
        if not isinstance(item, dict):
            continue
        date = str(item.get("xposed_date") or "")[:7]
        name = str(item.get("breach") or "?")
        result["breaches"].append(f"{name} ({date})" if date else name)
        fields.update(part.strip() for part in str(item.get("xposed_data") or "").split(";") if part.strip())
    result["count"] = len(details)
    result["fields"] = sorted(fields)
    metrics = data.get("BreachMetrics") or {}
    risk = (metrics.get("risk") or [{}])[0] if metrics.get("risk") else {}
    if isinstance(risk, dict) and risk.get("risk_label"):
        result["risk"] = f"{risk.get('risk_label')} ({risk.get('risk_score')})"
    strength = (metrics.get("passwords_strength") or [{}])[0] if metrics.get("passwords_strength") else {}
    if isinstance(strength, dict):
        plain, weak = int(strength.get("PlainText") or 0), int(strength.get("EasyToCrack") or 0)
        if plain or weak:
            result["weak_passwords"] = f"открытых: {plain}, слабых: {weak}"
    return result


def hibp_breaches(email: str) -> dict:
    result = {"source": "HIBP", "count": None, "breaches": [], "fields": [], "error": ""}
    key = os.getenv("WATSON_HIBP_API_KEY")
    if not key:
        return result
    throttle("hibp", 1.6)
    status, data = fetch_json(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='@.')}?truncateResponse=false",
        ttl=3600, timeout=20, headers={"hibp-api-key": key},
    )
    if status == 404:
        result["count"] = 0
        return result
    if status == 401:
        result["error"] = "неверный WATSON_HIBP_API_KEY"
        return result
    if status == 429:
        result["error"] = "rate limit HIBP, повторите позже"
        return result
    if not isinstance(data, list):
        result["error"] = f"HTTP {status}"
        return result
    result["count"] = len(data)
    fields: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        title = str(item.get("Title") or item.get("Name") or "?")
        date = str(item.get("BreachDate") or "")[:7]
        result["breaches"].append(f"{title} ({date})" if date else title)
        fields.update(str(field) for field in item.get("DataClasses") or [])
    result["fields"] = sorted(fields)
    return result


def add_breach_signals(rep: dict, identifier: str) -> None:
    value = str(identifier or "").strip()
    if not value:
        return
    kind = breach_kind(value)
    if kind == "phone":
        results = []
        if os.getenv("WATSON_LEAKCHECK_KEY"):
            results.append(leakcheck_pro(value, kind='phone'))
        if not results:
            rep["notes"].append("Бесплатные breach-источники по номеру телефона недоступны; при наличии WATSON_LEAKCHECK_KEY Watson проверит LeakCheck Pro (он поддерживает номер).")
            return
        # Handle only the collected phone results below instead of the usual email/username path.
        total, consulted, classes = 0, [], set()
        for item in results:
            source = item["source"]
            if item.get("error"):
                rep["notes"].append(f"{source}: {item['error']}")
                continue
            count = item.get("count")
            if count is None:
                continue
            consulted.append(source)
            total = max(total, count)
            add(rep, f"{source}: найдено записей", count)
            if item.get("breaches"):
                shown = item["breaches"][:20]
                extra = len(item["breaches"]) - len(shown)
                add(rep, f"{source}: источники (пример)", ", ".join(shown) + (f" и ещё {extra}" if extra > 0 else ""))
            if item.get("fields"):
                add(rep, f"{source}: категории данных", ", ".join(item["fields"]))
            if item.get("quota") is not None:
                add(rep, f"{source}: остаток запросов", item["quota"])
            classes.update(str(field).lower() for field in item.get("fields") or [])
        if consulted:
            add(rep, "Проверено breach-источников", ", ".join(consulted))
            rep["notes"].append("Возвращаются только названия утечек, даты и категории полей — не сами значения.")
            if total == 0:
                add(rep, "Найдено в утечках (телефон)", "нет")
                return
            rep["links"] += [("LeakCheck", "https://leakcheck.io/")]
            flag(rep, 1, f"Номер телефона встречается в {total} записях публичных утечек")
            if any("password" in field or "парол" in field for field in classes):
                flag(rep, 1, "Среди утёкших категорий — пароли: возможно повторное использование учёток")
        return
    query = value.lstrip("@") if kind == "username" else value
    results = [leakcheck_public(query)]
    if kind == "email":
        results.append(xposedornot_breaches(value))
        if os.getenv("WATSON_HIBP_API_KEY"):
            results.append(hibp_breaches(value))
    if os.getenv("WATSON_LEAKCHECK_KEY"):
        results.append(leakcheck_pro(query, kind=kind if kind in ('email', 'username', 'phone') else None))

    total, consulted, classes = 0, [], set()
    for item in results:
        source = item["source"]
        if item.get("error"):
            rep["notes"].append(f"{source}: {item['error']}")
            continue
        count = item.get("count")
        if count is None:
            continue
        consulted.append(source)
        total = max(total, count)
        add(rep, f"{source}: найдено записей", count)
        if item.get("breaches"):
            shown = item["breaches"][:20]
            extra = len(item["breaches"]) - len(shown)
            add(rep, f"{source}: источники (пример)", ", ".join(shown) + (f" и ещё {extra}" if extra > 0 else ""))
        if item.get("fields"):
            add(rep, f"{source}: категории данных", ", ".join(item["fields"]))
        if item.get("risk"):
            add(rep, f"{source}: оценка риска", item["risk"])
        if item.get("weak_passwords"):
            add(rep, f"{source}: качество паролей", item["weak_passwords"])
        if item.get("quota") is not None:
            add(rep, f"{source}: остаток запросов", item["quota"])
        classes.update(str(field).lower() for field in item.get("fields") or [])

    if not consulted:
        add(rep, "Breach-источники", "недоступны")
        return
    add(rep, "Проверено breach-источников", ", ".join(consulted))
    rep["notes"].append("Возвращаются только названия утечек, даты и категории полей — не сами значения.")
    rep["notes"].append("Наличие идентификатора в утечке не доказывает мошенничество; это зацепка для проверки повторного использования учётных данных.")
    if total == 0:
        add(rep, "Найдено в утечках", "нет")
        return
    rep["links"] += [("LeakCheck", "https://leakcheck.io/"), ("XposedOrNot", "https://xposedornot.com/data-breach-check")]
    if kind == "email":
        rep["links"].append(("Have I Been Pwned", f"https://haveibeenpwned.com/account/{quote(value, safe='@.')}"))
    if kind == "username":
        rep["notes"].append("Совпадения по username — слабая зацепка: ник не уникален между сервисами, поэтому в оценку риска они не входят.")
        return
    flag(rep, 1, f"Идентификатор встречается в {total} записях публичных утечек")
    if any("password" in field or "парол" in field for field in classes):
        flag(rep, 1, "Среди утёкших категорий — пароли: возможно повторное использование учёток")


def scan_breach(target: str) -> dict:
    value = target.strip()
    kind = breach_kind(value)
    rep = new_report("Утечки (breach-статус)", value)
    remember(rep, {"email": "emails", "phone": "phones"}.get(kind, "usernames"), value if kind != "username" else value.lstrip("@"))
    add_breach_signals(rep, value)
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
    if re.search(r"\.(png|jpe?g|gif|webp|bmp|tiff?)$", target, re.I):
        return "image"
    if re.search(r"^https?://.*\.(png|jpe?g|gif|webp|bmp|tiff?)(\?.*)?$", target, re.I):
        return "image"
    if re.search(r"^(https?://)?[\w.-]+\.[a-z]{2,}(/.*)?$", target, re.I):
        return "domain"
    return "user"


SCANNERS = {"tg": scan_telegram, "id": scan_id, "phone": scan_phone, "email": scan_email, "user": scan_username, "domain": scan_domain, "crypto": scan_crypto, "image": scan_image, "export": scan_export, "evidence": scan_evidence, "breach": scan_breach, "mailaccess": scan_mailaccess, "investigate": scan_mailaccess}


def run(kind: str, target: str, deep: bool = False, sherlock: bool = False, maigret: bool = False, breach: bool = True) -> dict:
    rep = SCANNERS[kind](target)
    if breach and kind in ("tg", "email", "user", "mailaccess", "investigate"):
        add_breach_signals(rep, telegram_slug(target) if kind == "tg" else target)
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


def format_report(rep: dict) -> str:
    score, level = risk(rep)
    lines = [f"=== {rep['type']}: {rep['target']} ==="]
    for label, value in rep["findings"]:
        lines.append(f"  {label}: {value}")
    lines.append(f"\n  Оценка риска: {level} ({score})")
    for points, reason in rep["flags"]:
        if reason:
            lines.append(f"   [+{points}] {reason}")
    for note in rep["notes"]:
        lines.append(f"  * {note}")
    for name, url in rep["links"]:
        lines.append(f"  -> {name}: {url}")
    lines.append("\n  Оценка эвристическая. Не публикуйте персональные данные.")
    return "\n".join(lines)


def print_report(rep: dict) -> None:
    print("\n" + format_report(rep))


RISK_COLORS = {"низкий": "#2e7d32", "средний": "#ef6c00", "высокий": "#c62828"}


REPORT_CSS = """
*{box-sizing:border-box}
:root{--bg:#f5f6f8;--card:#fff;--fg:#171a1f;--muted:#67707c;--line:#dde1e7;--chip:#eef1f5;--accent:#2f6fed}
@media (prefers-color-scheme:dark){
  :root{--bg:#0e1116;--card:#161a20;--fg:#e7eaef;--muted:#98a2b0;--line:#282f38;--chip:#1e242c;--accent:#7aa2ff}
}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);line-height:1.45;
  font-family:system-ui,-apple-system,"Segoe UI","Helvetica Neue",Arial,"DejaVu Sans",sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:1.4rem 1rem 3rem}
header h1{margin:0;font-size:1.5rem}
.meta{color:var(--muted);font-size:.82rem;margin:.15rem 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem 1.15rem;
  margin:1rem 0;break-inside:avoid;page-break-inside:avoid}
.cardwrap{break-inside:avoid;page-break-inside:avoid}
.head{display:flex;gap:.8rem;align-items:flex-start;justify-content:space-between;flex-wrap:wrap}
.kind{font-size:.72rem;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
h2{margin:.15rem 0 .3rem;font-size:1.12rem;word-break:break-word}
h3{margin:1.05rem 0 .4rem;font-size:.76rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.risk{display:inline-block;color:#fff;padding:.3rem .75rem;border-radius:999px;
  font-size:.86rem;font-weight:600;white-space:nowrap;flex:none}
.pill{display:inline-block;color:#fff;padding:.12rem .55rem;border-radius:999px;font-size:.78rem;font-weight:600}
table{border-collapse:collapse;width:100%}
th,td{padding:.4rem .5rem;border-bottom:1px solid var(--line);text-align:left;
  vertical-align:top;word-break:break-word;font-size:.92rem}
th{font-weight:600}
table.data th{width:34%;color:var(--muted)}
thead th{width:auto;color:var(--muted);font-size:.76rem;letter-spacing:.05em;text-transform:uppercase}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
tr:last-child td,tr:last-child th{border-bottom:0}
ul{margin:.2rem 0;padding-left:1.1rem}
li{margin:.2rem 0}
.pts{display:inline-block;min-width:2.5rem;font-weight:700;font-variant-numeric:tabular-nums;color:#c62828}
.muted,.notes li{color:var(--muted);font-size:.82rem}
.links{display:flex;flex-wrap:wrap;gap:.35rem}
.btn{display:inline-block;padding:.35rem .7rem;border:1px solid var(--line);border-radius:8px;
  background:var(--chip);color:var(--fg);text-decoration:none;font-size:.85rem}
.btn:hover{border-color:var(--accent)}
a{color:var(--accent)}
.footer{color:var(--muted);font-size:.8rem;text-align:center;margin:2rem 0 0}
.tbar{display:flex;gap:.4rem;align-items:center;margin:.7rem 0 .3rem;flex-wrap:wrap}
.tbar input{flex:1 1 12rem;min-width:0;padding:.4rem .6rem;border:1px solid var(--line);
  border-radius:8px;background:var(--bg);color:var(--fg);font-size:.85rem}
.tbar button{padding:.35rem .65rem;border:1px solid var(--line);border-radius:8px;
  background:var(--chip);color:var(--fg);font-size:.95rem;cursor:pointer}
.tbar button:disabled{opacity:.4;cursor:default}
.tinfo{color:var(--muted);font-size:.8rem;font-variant-numeric:tabular-nums}
@media (max-width:600px){
  .wrap{padding:1rem .7rem 2rem}
  .head{gap:.5rem}
  table.data tr{display:block;margin:.55rem 0}
  table.data th,table.data td{display:block;width:auto;border:0;padding:.05rem 0}
  table.data th{font-size:.78rem}
}
@media print{
  :root{--bg:#fff;--card:#fff;--fg:#000;--muted:#333;--line:#999;--chip:#f2f2f2;--accent:#000}
  body{background:#fff}
  .wrap{padding:0;max-width:none}
  .card{border:1px solid #999;break-inside:avoid;page-break-inside:avoid;margin:.6rem 0}
  .tbar{display:none}
  tbody tr{display:table-row !important}
  a{color:#000;text-decoration:none}
  .btn{border:1px solid #999;background:#f5f5f5;color:#000}
  .pts{color:#000}
}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
@page{margin:12mm}
"""


TABLE_JS = """
(function () {
  function wire(table) {
    var body = table.tBodies[0];
    if (!body) return;
    var rows = Array.prototype.slice.call(body.rows);
    if (rows.length <= 10) return;
    var page = 0, query = "";

    var bar = document.createElement("div");
    bar.className = "tbar";

    var input = document.createElement("input");
    input.type = "search";
    input.placeholder = "Поиск по таблице\\u2026";
    input.setAttribute("aria-label", "Поиск по таблице");

    var info = document.createElement("span");
    info.className = "tinfo";

    var prev = document.createElement("button");
    prev.type = "button";
    prev.textContent = "\\u2039";
    prev.setAttribute("aria-label", "Предыдущая страница");

    var next = document.createElement("button");
    next.type = "button";
    next.textContent = "\\u203a";
    next.setAttribute("aria-label", "Следующая страница");

    bar.appendChild(input);
    bar.appendChild(info);
    bar.appendChild(prev);
    bar.appendChild(next);
    table.parentNode.insertBefore(bar, table);

    function render() {
      var filtered = rows.filter(function (row) {
        return !query || row.textContent.toLowerCase().indexOf(query) !== -1;
      });
      var pages = Math.max(1, Math.ceil(filtered.length / 10));
      if (page > pages - 1) page = pages - 1;
      if (page < 0) page = 0;
      rows.forEach(function (row) { row.style.display = "none"; });
      filtered.slice(page * 10, page * 10 + 10).forEach(function (row) { row.style.display = ""; });
      info.textContent = filtered.length ? (page + 1) + "/" + pages + " \\u00b7 " + filtered.length : "0";
      prev.disabled = page <= 0;
      next.disabled = page >= pages - 1;
    }

    input.addEventListener("input", function () {
      query = input.value.trim().toLowerCase();
      page = 0;
      render();
    });
    prev.addEventListener("click", function () { if (page > 0) { page -= 1; render(); } });
    next.addEventListener("click", function () { page += 1; render(); });
    render();
  }

  function init() {
    var tables = document.querySelectorAll("table[data-paginate]");
    Array.prototype.forEach.call(tables, wire);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
"""


def html_report(rep: dict) -> str:
    score, level = risk(rep)
    escape = html.escape
    checked = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    findings = list(rep["findings"])
    rows = "".join(f"<tr><th>{escape(str(label))}</th><td>{escape(str(value))}</td></tr>" for label, value in findings)
    paginate = " data-paginate" if len(findings) > 10 else ""
    data = f"<table class='data'{paginate}><tbody>{rows}</tbody></table>" if rows else "<p class='muted'>данных нет</p>"
    ordered_flags = sorted(
        ((points, reason) for points, reason in rep["flags"] if reason),
        key=lambda item: item[0],
        reverse=True,
    )
    flags = "".join(f"<li><span class='pts'>+{points}</span> {escape(str(reason))}</li>" for points, reason in ordered_flags)
    flags = flags or "<li class='muted'>признаков не найдено</li>"
    notes = "".join(f"<li>{escape(str(note))}</li>" for note in rep["notes"]) or "<li class='muted'>заметок нет</li>"
    allowed = ("http://", "https://", "tg://")
    links = "".join(
        f"<a class='btn' href='{escape(url, quote=True)}' target='_blank' rel='noopener noreferrer'>{escape(str(name))}</a>"
        for name, url in rep["links"]
        if isinstance(url, str) and url.lower().startswith(allowed)
    )
    links = links or "<span class='muted'>ссылок нет</span>"
    return (
        "<section class='card'>"
        "<div class='head'><div>"
        f"<div class='kind'>{escape(str(rep['type']))}</div>"
        f"<h2>{escape(str(rep['target']))}</h2>"
        f"<div class='meta'>Проверено: {checked}</div>"
        "</div>"
        f"<span class='risk' style='background:{RISK_COLORS[level]}'>Риск: {escape(level)} ({score})</span>"
        "</div>"
        "<h3>Данные</h3>" + data +
        "<h3>Признаки риска</h3><ul class='flags'>" + flags + "</ul>"
        "<h3>Заметки</h3><ul class='notes'>" + notes + "</ul>"
        "<h3>Ссылки для ручной проверки</h3><div class='links'>" + links + "</div>"
        "</section>"
    )


def render_page(reports: list[dict]) -> str:
    escape = html.escape
    cards = "".join(f"<div class='cardwrap' id='t{index}'>{html_report(rep)}</div>" for index, rep in enumerate(reports))
    summary = ""
    if len(reports) > 1:
        rows = []
        for index, rep in enumerate(reports):
            score, level = risk(rep)
            rows.append(
                f"<tr><td><a href='#t{index}'>{escape(str(rep['target']))}</a></td>"
                f"<td><span class='pill' style='background:{RISK_COLORS[level]}'>{escape(level)}</span></td>"
                f"<td class='num'>{score}</td></tr>"
            )
        paginate = " data-paginate" if len(rows) > 10 else ""
        summary = (
            "<section class='card'><h2>Сводка</h2>"
            f"<p class='meta'>Целей: {len(rows)}. Отсортировано по риску.</p>"
            f"<table class='summary'{paginate}><thead><tr><th>Цель</th><th>Риск</th><th class='num'>Баллы</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></section>"
        )
    stamp = escape(dt.datetime.now().strftime("%Y-%m-%d %H:%M"))
    return (
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Watson report</title><style>" + REPORT_CSS + "</style></head>"
        "<body><div class='wrap'>"
        "<header><h1>Watson</h1><p class='meta'>Сформирован " + stamp +
        ". Оценка эвристическая, не доказательство.</p></header>"
        + summary + cards +
        "<footer class='footer'>Оценка эвристическая, не доказательство. Не публикуйте персональные данные без законного основания.</footer>"
        "</div><script>" + TABLE_JS + "</script></body></html>"
    )


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
            lines += [f"- +{points}: {reason}" for points, reason in sorted(rep["flags"], reverse=True) if reason]
            lines.append("")
        if rep["notes"]:
            lines += ["### Заметки", ""]
            lines += [f"- {note}" for note in rep["notes"]]
            lines.append("")
    return "\n".join(lines)


def telegram_bot_api(token: str, method: str, params: dict | None = None, timeout: int = 25):
    url = f"https://api.telegram.org/bot{token}/{method}"
    if params:
        query = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in params.items())
        url += "?" + query
    status, data = fetch_json(url, ttl=0, timeout=timeout)
    return status, data if isinstance(data, dict) else {}


def send_telegram_message(token: str, chat_id, text: str) -> None:
    limit = 3800
    for chunk in [text[i:i + limit] for i in range(0, len(text), limit)] or [""]:
        payload = json.dumps({"chat_id": chat_id, "text": chunk}, ensure_ascii=False).encode("utf-8")
        request = Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={**UA, "Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except Exception as exc:
            print(f"Telegram send failed: {exc}", file=sys.stderr)
            return
        if not (isinstance(data, dict) and data.get("ok")):
            print(f"Telegram send failed: {data}", file=sys.stderr)


def bot_help_text() -> str:
    return (
        "Watson — OSINT-триаж. Отправьте цель одной строкой: @username, +7..., email, домен, адрес, /path/image.jpg или id 12345.\n"
        "Команды: /help, /scan <цель>, /scan mailaccess <email> (аккаунты по email), /deep доступен только в CLI.\n"
        "Оценка эвристическая, не доказательство."
    )


def bot_process_target(token: str, chat_id, text: str, deep: bool = False, sherlock: bool = False, maigret: bool = False, breach: bool = True) -> None:
    line = text.strip()
    if line.startswith("/scan "):
        line = line[6:].strip()
    if not line:
        send_telegram_message(token, chat_id, bot_help_text())
        return
    try:
        parts = line.split(None, 1)
        kind, target = (parts[0], parts[1]) if parts[0] in SCANNERS and len(parts) > 1 else (detect(line), line)
        report = run(kind, target, deep=deep, sherlock=sherlock, maigret=maigret, breach=breach)
        send_telegram_message(token, chat_id, format_report(report))
    except (OSError, ValueError) as exc:
        send_telegram_message(token, chat_id, f"Ошибка: {exc}")


def run_telegram_bot(token: str, deep: bool = False, sherlock: bool = False, maigret: bool = False, breach: bool = True, offset: int = 0) -> int:
    print("Watson Telegram bot запущен. Ctrl+C для остановки.", file=sys.stderr)
    try:
        while True:
            status, data = telegram_bot_api(token, "getUpdates", {"offset": offset, "timeout": 20}, timeout=30)
            if not (isinstance(data, dict) and data.get("ok")):
                print(f"getUpdates failed ({status}): {data}", file=sys.stderr)
                time.sleep(3)
                continue
            for update in data.get("result", []) or []:
                offset = int(update.get("update_id", 0)) + 1
                message = update.get("message") or update.get("edited_message") or {}
                chat = message.get("chat") or {}
                chat_id = chat.get("id")
                text = message.get("text") or ""
                if chat_id is None or not text:
                    continue
                if text.startswith("/start") or text.startswith("/help"):
                    send_telegram_message(token, chat_id, bot_help_text())
                elif text.startswith("/scan") or not text.startswith("/"):
                    bot_process_target(token, chat_id, text, deep=deep, sherlock=sherlock, maigret=maigret, breach=breach)
                else:
                    send_telegram_message(token, chat_id, "Неизвестная команда. Используйте /help.")
    except KeyboardInterrupt:
        print("\nWatson Telegram bot остановлен.", file=sys.stderr)
        return 0
    return 0


# Interactive TUI ------------------------------------------------------------
# Полноэкранный интерфейс на стандартном curses: без внешних зависимостей.

KIND_INFO = [
    ("tg", "Telegram-аккаунт", "@username, t.me/… или ссылка"),
    ("id", "Telegram ID", "числовой ID, оценка даты регистрации"),
    ("phone", "Телефон", "+7…, соцсети и мессенджеры"),
    ("email", "Email", "адрес, домены, утечки"),
    ("mailaccess", "Email-расследование", "аккаунты по email (MailAccess)"),
    ("user", "Username", "ник для Sherlock / Maigret"),
    ("domain", "Домен или сайт", "example.com"),
    ("crypto", "Крипто-адрес", "BTC, ETH, USDT"),
    ("image", "Изображение", "путь к файлу или URL"),
    ("evidence", "Материалы дела", "локальный JSON/CSV/TXT"),
    ("export", "Telegram-экспорт", "JSON из Telegram Desktop"),
    ("breach", "Утечки", "email, username, телефон"),
]

TOGGLES = [
    ("deep", "Глубокий Telegram (Telethon-сеанс)"),
    ("sherlock", "Sherlock: поиск username по сайтам"),
    ("maigret", "Maigret: расширенный поиск username"),
    ("breach", "Проверка утечек (email / username / телефон)"),
]

SPINNER_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_ASCII = "|/-\\"

_ASCII_GLYPHS = {
    "W": ["__        __", "\\ \\      / /", " \\ \\ /\\ / / ", "  \\ V  V /  ", "   \\_/\\_/   "],
    "A": ["    _    ", "   / \\   ", "  / _ \\  ", " / ___ \\ ", "/_/   \\_\\"],
    "T": [" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "],
    "S": [" ____  ", "/ ___| ", "\\___ \\ ", " ___) |", "|____/ "],
    "O": ["  ___  ", " / _ \\ ", "| | | |", "| |_| |", " \\___/ "],
    "N": [" _   _ ", "| \\ | |", "|  \\| |", "| |\\  |", "|_| \\_|"],
}

BANNER_UNICODE = [
    "╦ ╦╔═╗╔╦╗╔═╗╔═╗╔╗╔",
    "║║║╠═╣ ║ ╚═╗║╣ ║║║",
    "╚╩╝╩ ╩ ╩ ╚═╝╚═╝╝╚╝",
]


def _ascii_banner(word: str = "WATSON") -> list[str]:
    rows = ["" for _ in range(5)]
    for index, letter in enumerate(word.upper()):
        glyph = _ASCII_GLYPHS.get(letter, ["     "] * 5)
        for row in range(5):
            rows[row] += ("" if index == 0 else " ") + glyph[row]
    return rows


def _utf8_ok() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower()
    try:
        "╦═╗".encode(encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _char_width(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _wcswidth(text: str) -> int:
    return sum(_char_width(ch) for ch in text)


def _clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    out, used = [], 0
    for ch in text:
        char_width = _char_width(ch)
        if used + char_width > width:
            break
        out.append(ch)
        used += char_width
    return "".join(out)


def _wrap(text: str, width: int) -> list[str]:
    if width <= 0:
        return [text]
    lines = []
    for raw in text.split("\n"):
        if not raw:
            lines.append("")
            continue
        current = ""
        for word in raw.split(" "):
            while _wcswidth(word) > width:
                if current:
                    lines.append(current)
                    current = ""
                chunk = _clip(word, width)
                lines.append(chunk)
                word = word[len(chunk):]
            if not word:
                continue
            candidate = word if not current else current + " " + word
            if _wcswidth(candidate) <= width:
                current = candidate
            else:
                lines.append(current)
                current = word
        lines.append(current)
    return lines


def default_output_path(kind: str, target: str, ext: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{kind}_{target}").strip("_")[:60] or "report"
    return str(Path.cwd() / f"watson_{safe}.{ext}")


def write_report_file(rep: dict, fmt: str, path: str) -> str:
    destination = Path(path).expanduser()
    if fmt == "html":
        destination.write_text(render_page([rep]), encoding="utf-8")
    elif fmt == "json":
        destination.write_text(json.dumps([rep], ensure_ascii=False, indent=2), encoding="utf-8")
    elif fmt == "md":
        destination.write_text(markdown_report([rep]), encoding="utf-8")
    elif fmt == "csv":
        score, level = risk(rep)
        with destination.open("w", newline="", encoding="utf-8-sig") as output:
            writer = csv.writer(output)
            writer.writerow(["тип", "цель", "риск", "баллы", "признаки"])
            writer.writerow([rep["type"], rep["target"], level, score, " | ".join(r for _, r in rep["flags"])])
    else:
        raise ValueError(f"неизвестный формат: {fmt}")
    return str(destination)


class _Quit(Exception):
    pass


class WatsonTUI:
    def __init__(self, stdscr, options: dict):
        self.scr = stdscr
        self.opt = dict(options)
        self.results: list[dict] = []
        self.status = ""
        self.screen = "home"
        self.home_index = 0
        self.kind_index = 0
        self.opt_index = 0
        self.list_index = 0
        self.view_index = 0
        self.save_index = 0
        self.save_fmt = "html"
        self.scroll = 0
        self.max_scroll = 0
        self.frame = 0
        self.kind = "tg"
        self.input = ""
        self.input_pos = 0
        self.running = False
        self.scan_error = None
        self.scan_result = None
        self.toggle_mode = "run"
        self.utf8 = True
        self.banner: list[str] = []
        self.spinner = SPINNER_ASCII
        self.colors: dict[str, int] = {}

    # -- инфраструктура -----------------------------------------------------
    def setup(self) -> None:
        self.utf8 = _utf8_ok()
        self.banner = BANNER_UNICODE if self.utf8 else _ascii_banner("WATSON")
        self.spinner = SPINNER_UNICODE if self.utf8 else SPINNER_ASCII
        self.colors = {"dim": curses.A_DIM, "bold": curses.A_BOLD}
        if curses.has_colors():
            try:
                curses.start_color()
                try:
                    curses.use_default_colors()
                    background = -1
                except curses.error:
                    background = curses.COLOR_BLACK
                palette = [
                    ("accent", curses.COLOR_CYAN, True),
                    ("low", curses.COLOR_GREEN, False),
                    ("medium", curses.COLOR_YELLOW, False),
                    ("high", curses.COLOR_RED, False),
                    ("link", curses.COLOR_CYAN, False),
                    ("section", curses.COLOR_MAGENTA, True),
                ]
                for pair, (name, foreground, bold) in enumerate(palette, start=1):
                    try:
                        curses.init_pair(pair, foreground, background)
                        attr = curses.color_pair(pair)
                        self.colors[name] = attr | (curses.A_BOLD if bold else 0)
                    except curses.error:
                        pass
            except curses.error:
                pass
        try:
            self.scr.keypad(True)
        except curses.error:
            pass
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        try:
            curses.set_escdelay(25)
        except (AttributeError, curses.error):
            pass

    def c(self, name: str) -> int:
        return self.colors.get(name, 0)

    def risk_attr(self, level: str) -> int:
        return {"низкий": self.c("low"), "средний": self.c("medium"), "высокий": self.c("high")}.get(level, 0)

    def dims(self):
        return self.scr.getmaxyx()

    def safe_add(self, y: int, x: int, text: str, attr: int = 0) -> None:
        height, width = self.dims()
        if y < 0 or y >= height or x < 0 or x >= width:
            return
        try:
            self.scr.addstr(y, x, _clip(text, width - x), attr)
        except curses.error:
            pass

    def is_enter(self, key) -> bool:
        return key in ("\n", "\r", curses.KEY_ENTER) or key == 10

    def is_esc(self, key) -> bool:
        return key == "\x1b" or key == 27

    def is_backspace(self, key) -> bool:
        return key in ("\x7f", "\b", curses.KEY_BACKSPACE) or key == 263

    def edit_input(self, key) -> bool:
        """Обрабатывает одну клавишу для однострочного ввода. True — обработано."""
        if self.is_backspace(key):
            if self.input_pos > 0:
                self.input = self.input[: self.input_pos - 1] + self.input[self.input_pos:]
                self.input_pos -= 1
            return True
        if key == curses.KEY_DC:
            self.input = self.input[: self.input_pos] + self.input[self.input_pos + 1:]
            return True
        if key == curses.KEY_LEFT:
            self.input_pos = max(0, self.input_pos - 1)
            return True
        if key == curses.KEY_RIGHT:
            self.input_pos = min(len(self.input), self.input_pos + 1)
            return True
        if key == curses.KEY_HOME or key == "\x01":
            self.input_pos = 0
            return True
        if key == curses.KEY_END or key == "\x05":
            self.input_pos = len(self.input)
            return True
        if key == "\x15":
            self.input = ""
            self.input_pos = 0
            return True
        if isinstance(key, str) and len(key) == 1 and key.isprintable():
            self.input = self.input[: self.input_pos] + key + self.input[self.input_pos:]
            self.input_pos += 1
            return True
        return False

    # -- главный цикл -------------------------------------------------------
    def run(self) -> int:
        self.setup()
        while True:
            self.draw()
            self.scr.timeout(160 if self.screen == "run" else -1)
            try:
                key = self.scr.get_wch()
            except curses.error:
                key = None
            except KeyboardInterrupt:
                break
            if key == curses.KEY_RESIZE:
                continue
            if key is None:
                if self.screen == "run" and not self.running:
                    self.finish_scan()
                self.frame += 1
                continue
            handler = getattr(self, "_key_" + self.screen, None)
            try:
                if handler and handler(key) == "quit":
                    break
            except _Quit:
                break
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        return 0

    # -- рисование ----------------------------------------------------------
    def draw(self) -> None:
        self.scr.erase()
        top = self.draw_header()
        drawer = getattr(self, "_draw_" + self.screen, None)
        if drawer:
            drawer(top)
        self.draw_status()
        self.draw_footer()
        visible = self.screen in ("target", "savepath")
        try:
            curses.curs_set(1 if visible else 0)
        except curses.error:
            pass
        self.scr.refresh()

    def draw_header(self) -> int:
        height, width = self.dims()
        y = 0
        if height >= 17:
            y = 1
            for offset, line in enumerate(self.banner):
                x = max(0, (width - _wcswidth(line)) // 2)
                self.safe_add(y + offset, x, line, self.c("accent"))
            y += len(self.banner) + 1
        else:
            title = "W A T S O N"
            self.safe_add(y, max(0, (width - len(title)) // 2), title, self.c("accent"))
            y += 2
        separator = "─" * width if self.utf8 else "-" * width
        self.safe_add(y, 0, separator, self.c("dim"))
        return y + 1

    def draw_footer(self, text: str = "") -> None:
        height, width = self.dims()
        self.safe_add(height - 1, 0, " " * width, curses.A_REVERSE)
        self.safe_add(height - 1, 0, " " + _clip(text, width - 2), curses.A_REVERSE)

    def draw_status(self) -> None:
        height, width = self.dims()
        if self.status:
            self.safe_add(height - 2, 0, " " * width)
            self.safe_add(height - 2, 0, "  " + _clip(self.status, width - 3), self.c("dim"))

    def menu(self, y: int, items: list[str], index: int, indent: int = 2) -> int:
        height, width = self.dims()
        bottom = height - 3
        rows = max(1, bottom - y + 1)
        offset = 0
        if index >= rows:
            offset = index - rows + 1
        marker = "❯ " if self.utf8 else "> "
        for i in range(offset, min(len(items), offset + rows)):
            selected = i == index
            label = (marker if selected else "  ") + items[i]
            attr = curses.A_REVERSE if selected else 0
            self.safe_add(y + (i - offset), indent, _clip(label, width - indent - 1), attr)
        return offset

    # -- экраны: отрисовка --------------------------------------------------
    def home_items(self) -> list[tuple[str, str]]:
        items = [("new", "Новая проверка")]
        if self.results:
            items.append(("results", f"Результаты ({len(self.results)})"))
        items += [("settings", "Настройки"), ("help", "Справка"), ("quit", "Выход")]
        return items

    def _draw_home(self, top: int) -> None:
        items = self.home_items()
        self.menu(top, [label for _, label in items], self.home_index)
        self.draw_footer("↑/↓ выбрать · Enter открыть · q выход")

    def _draw_kind(self, top: int) -> None:
        self.safe_add(top, 2, "Выберите тип проверки", self.c("section"))
        labels = [f"{title:<22} {hint}" for _, title, hint in KIND_INFO]
        self.menu(top + 2, labels, self.kind_index)
        self.draw_footer("↑/↓ выбрать · Enter далее · Esc назад")

    def _draw_target(self, top: int) -> None:
        width = self.dims()[1]
        title, hint = next((t, h) for k, t, h in KIND_INFO if k == self.kind)
        self.safe_add(top, 2, f"Тип: {title}", self.c("section"))
        self.safe_add(top + 1, 2, hint, self.c("dim"))
        label = "Цель:"
        y = top + 3
        self.safe_add(y, 2, label, self.c("bold"))
        x = 2 + len(label) + 1
        avail = max(1, width - x - 2)
        self.safe_add(y, x, " " * (width - x))
        start = 0
        while start < self.input_pos and _wcswidth(self.input[start : self.input_pos]) > avail - 1:
            start += 1
        self.safe_add(y, x, _clip(self.input[start:], avail), self.c("accent"))
        cursor_x = x + _wcswidth(self.input[start : self.input_pos])
        try:
            self.scr.move(y, min(cursor_x, width - 2))
        except curses.error:
            pass
        self.draw_footer("Enter — далее · Esc — назад · Ctrl+U — очистить")

    def _draw_options(self, top: int) -> None:
        heading = "Параметры проверки" if self.toggle_mode == "run" else "Настройки проверок"
        self.safe_add(top, 2, heading, self.c("section"))
        if self.toggle_mode == "run":
            title = next((t for k, t, _ in KIND_INFO if k == self.kind), self.kind)
            self.safe_add(top + 1, 2, f"{title}: {self.target}", self.c("dim"))
        labels = []
        for name, description in TOGGLES:
            box = "[x]" if self.opt.get(name) else "[ ]"
            labels.append(f"{box} {description}")
        labels.append("▶ Запустить проверку" if self.toggle_mode == "run" else "Готово")
        self.menu(top + 3, labels, self.opt_index)
        footer = "↑/↓ выбрать · Пробел/Enter — переключить · r — запустить · Esc назад"
        if self.toggle_mode != "run":
            footer = "↑/↓ выбрать · Пробел/Enter — переключить · Esc — сохранить"
        self.draw_footer(footer)

    def _draw_run(self, top: int) -> None:
        width = self.dims()[1]
        spin = self.spinner[self.frame % len(self.spinner)]
        title = next((t for k, t, _ in KIND_INFO if k == self.kind), self.kind)
        center_y = max(top + 1, self.dims()[0] // 2 - 1)
        line = f"{spin}  Выполняется: {title}"
        self.safe_add(center_y, max(0, (width - _wcswidth(line)) // 2), line, self.c("accent"))
        target_line = _clip(self.target, width - 4)
        self.safe_add(center_y + 1, max(0, (width - _wcswidth(target_line)) // 2), target_line, self.c("dim"))
        self.draw_footer("Идёт сбор данных из открытых источников…")

    def report_lines(self, rep: dict, width: int) -> list[tuple[str, int]]:
        score, level = risk(rep)
        out: list[tuple[str, int]] = []

        def add(text: str, attr: int = 0) -> None:
            for line in _wrap(text, width) or [""]:
                out.append((line, attr))

        add(f"{rep['type'].upper()} · {rep['target']}", self.c("accent") | curses.A_BOLD)
        add(f"Оценка риска: {level} ({score})", self.risk_attr(level) | curses.A_BOLD)
        add("")
        add("ДАННЫЕ", self.c("section") | curses.A_BOLD)
        if rep["findings"]:
            for label, value in rep["findings"]:
                add(f"  • {label}: {value}")
        else:
            add("  нет данных", self.c("dim"))
        add("")
        add("ПРИЗНАКИ РИСКА", self.c("section") | curses.A_BOLD)
        notable = sorted((item for item in rep["flags"] if item[1]), key=lambda item: item[0], reverse=True)
        if notable:
            for points, reason in notable:
                add(f"  +{points}  {reason}", self.c("high"))
        else:
            add("  признаков не найдено", self.c("dim"))
        if rep["notes"]:
            add("")
            add("ЗАМЕТКИ", self.c("section") | curses.A_BOLD)
            for note in rep["notes"]:
                add(f"  * {note}", self.c("dim"))
        if rep["links"]:
            add("")
            add("ССЫЛКИ ДЛЯ ПРОВЕРКИ", self.c("section") | curses.A_BOLD)
            for name, url in rep["links"]:
                add(f"  → {name}: {url}", self.c("link"))
        add("")
        add("Оценка эвристическая, не доказательство.", self.c("dim"))
        return out

    def _draw_result(self, top: int) -> None:
        height, width = self.dims()
        rep = self.results[self.view_index]
        lines = self.report_lines(rep, width - 6)
        bottom = height - 3
        rows = max(1, bottom - top + 1)
        self.max_scroll = max(0, len(lines) - rows)
        self.scroll = max(0, min(self.scroll, self.max_scroll))
        for i in range(self.scroll, min(len(lines), self.scroll + rows)):
            text, attr = lines[i]
            self.safe_add(top + (i - self.scroll), 3, text, attr)
        position = ""
        if self.max_scroll:
            position = f"  [{self.scroll + 1}-{min(len(lines), self.scroll + rows)}/{len(lines)}]"
        self.draw_footer("↑/↓ прокрутка · s сохранить · r повторить · Esc назад" + position)

    def _draw_results(self, top: int) -> None:
        self.safe_add(top, 2, "Сохранённые результаты (текущий сеанс)", self.c("section"))
        items = []
        for rep in self.results:
            _, level = risk(rep)
            items.append(f"{level:<7} · {rep['type']}: {rep['target']}")
        self.menu(top + 2, items, self.list_index)
        self.draw_footer("↑/↓ выбрать · Enter открыть · Esc назад")

    def _draw_save(self, top: int) -> None:
        self.safe_add(top, 2, "Сохранить отчёт в файл", self.c("section"))
        items = [
            "HTML — оформленный отчёт (открывается в браузере)",
            "JSON — машинно-читаемые данные",
            "CSV  — сводная таблица",
            "Markdown — текстовый отчёт",
        ]
        self.menu(top + 2, items, self.save_index)
        self.draw_footer("↑/↓ выбрать формат · Enter далее · Esc назад")

    def _draw_savepath(self, top: int) -> None:
        width = self.dims()[1]
        self.safe_add(top, 2, "Путь для сохранения (Enter — записать файл)", self.c("section"))
        label = "Файл:"
        y = top + 2
        self.safe_add(y, 2, label, self.c("bold"))
        x = 2 + len(label) + 1
        avail = max(1, width - x - 2)
        self.safe_add(y, x, " " * (width - x))
        start = 0
        while start < self.input_pos and _wcswidth(self.input[start : self.input_pos]) > avail - 1:
            start += 1
        self.safe_add(y, x, _clip(self.input[start:], avail), self.c("accent"))
        cursor_x = x + _wcswidth(self.input[start : self.input_pos])
        try:
            self.scr.move(y, min(cursor_x, width - 2))
        except curses.error:
            pass
        self.draw_footer("Enter — сохранить · Esc — назад · Ctrl+U — очистить")

    def _draw_help(self, top: int) -> None:
        width = self.dims()[1]
        sections = [
            ("Навигация", [
                "↑ / ↓  — перемещение по меню и прокрутка",
                "Enter  — открыть / подтвердить",
                "Esc / q — назад, из главного меню — выход",
            ]),
            ("Типы проверок", [
                f"{title} — {hint}" for _, title, hint in KIND_INFO
            ]),
            ("Параметры", [
                "Глубокий Telegram требует установленного Telethon-сеанса.",
                "Sherlock / Maigret запускаются, только если установлены.",
                "Проверка утечек показывает статус, имена, даты и классы данных.",
            ]),
            ("О выводах", [
                "Все оценки эвристические и не являются доказательством.",
                "Не публикуйте персональные данные без законного основания.",
            ]),
            ("Экспорт", [
                "Из результата: s — сохранить HTML / JSON / CSV / Markdown.",
            ]),
        ]
        y = top
        bottom = self.dims()[0] - 3
        for heading, lines in sections:
            if y > bottom:
                break
            self.safe_add(y, 2, heading, self.c("section") | curses.A_BOLD)
            y += 1
            for line in lines:
                for wrapped in _wrap("  " + line, width - 4):
                    if y > bottom:
                        break
                    self.safe_add(y, 2, wrapped, self.c("dim"))
                    y += 1
            y += 1
        self.draw_footer("↑/↓ прокрутка · Esc / q — назад")

    # -- экраны: обработка клавиш ------------------------------------------
    def _key_home(self, key):
        items = self.home_items()
        if key in (curses.KEY_UP, "k"):
            self.home_index = (self.home_index - 1) % len(items)
        elif key in (curses.KEY_DOWN, "j"):
            self.home_index = (self.home_index + 1) % len(items)
        elif key == "q" or self.is_esc(key):
            raise _Quit
        elif self.is_enter(key):
            choice = items[self.home_index][0]
            if choice == "new":
                self.screen, self.kind_index, self.status = "kind", 0, ""
            elif choice == "results":
                self.screen, self.list_index, self.status = "results", 0, ""
            elif choice == "settings":
                self.toggle_mode, self.opt_index, self.screen = "settings", 0, "options"
            elif choice == "help":
                self.screen, self.status = "help", ""
            elif choice == "quit":
                raise _Quit
        return None

    def _key_kind(self, key):
        count = len(KIND_INFO)
        if self.is_esc(key) or key == "q":
            self.screen = "home"
        elif key in (curses.KEY_UP, "k"):
            self.kind_index = (self.kind_index - 1) % count
        elif key in (curses.KEY_DOWN, "j"):
            self.kind_index = (self.kind_index + 1) % count
        elif self.is_enter(key):
            self.kind = KIND_INFO[self.kind_index][0]
            self.input, self.input_pos, self.status = "", 0, ""
            self.screen = "target"
        return None

    def _key_target(self, key):
        if self.is_esc(key):
            self.screen = "kind"
        elif self.is_enter(key):
            if self.input.strip():
                self.target = self.input.strip()
                self.toggle_mode, self.opt_index, self.screen = "run", 0, "options"
            else:
                self.status = "Сначала введите цель"
        else:
            self.edit_input(key)
        return None

    def _key_options(self, key):
        count = len(TOGGLES) + 1
        if key in (curses.KEY_UP, "k"):
            self.opt_index = (self.opt_index - 1) % count
        elif key in (curses.KEY_DOWN, "j"):
            self.opt_index = (self.opt_index + 1) % count
        elif key == " ":
            if self.opt_index < len(TOGGLES):
                name = TOGGLES[self.opt_index][0]
                self.opt[name] = not self.opt.get(name)
        elif key == "r" and self.toggle_mode == "run":
            self.start_scan()
        elif self.is_enter(key):
            if self.opt_index < len(TOGGLES):
                name = TOGGLES[self.opt_index][0]
                self.opt[name] = not self.opt.get(name)
            elif self.toggle_mode == "run":
                self.start_scan()
            else:
                self.screen = "home"
        elif self.is_esc(key) or key == "q":
            self.screen = "target" if self.toggle_mode == "run" else "home"
            self.status = ""
        return None

    def _key_run(self, key):
        if key is None:
            return None
        if not self.running:
            self.finish_scan()
        return None

    def _key_result(self, key):
        page = max(1, self.dims()[0] - 8)
        if key in (curses.KEY_UP, "k"):
            self.scroll -= 1
        elif key in (curses.KEY_DOWN, "j"):
            self.scroll += 1
        elif key == curses.KEY_PPAGE:
            self.scroll -= page
        elif key == curses.KEY_NPAGE:
            self.scroll += page
        elif key == curses.KEY_HOME:
            self.scroll = 0
        elif key == curses.KEY_END:
            self.scroll = self.max_scroll
        elif key == "s":
            self.screen, self.save_index = "save", 0
        elif key == "r":
            self.start_scan()
        elif self.is_esc(key) or key == "q":
            self.screen, self.status = "home", ""
        return None

    def _key_results(self, key):
        count = len(self.results)
        if key in (curses.KEY_UP, "k"):
            self.list_index = (self.list_index - 1) % count
        elif key in (curses.KEY_DOWN, "j"):
            self.list_index = (self.list_index + 1) % count
        elif self.is_enter(key):
            self.view_index, self.scroll, self.screen = self.list_index, 0, "result"
        elif self.is_esc(key) or key == "q":
            self.screen = "home"
        return None

    def _key_save(self, key):
        if key in (curses.KEY_UP, "k"):
            self.save_index = (self.save_index - 1) % 4
        elif key in (curses.KEY_DOWN, "j"):
            self.save_index = (self.save_index + 1) % 4
        elif self.is_enter(key):
            self.save_fmt = ["html", "json", "csv", "md"][self.save_index]
            rep = self.results[self.view_index]
            self.input = default_output_path(rep["type"], rep["target"], self.save_fmt)
            self.input_pos = len(self.input)
            self.screen = "savepath"
        elif self.is_esc(key) or key == "q":
            self.screen = "result"
        return None

    def _key_savepath(self, key):
        if self.is_esc(key):
            self.screen = "save"
        elif self.is_enter(key):
            rep = self.results[self.view_index]
            try:
                path = write_report_file(rep, self.save_fmt, self.input.strip())
                self.status = f"Сохранено: {path}"
                self.screen = "result"
            except (OSError, ValueError) as exc:
                self.status = f"Ошибка сохранения: {exc}"
        else:
            self.edit_input(key)
        return None

    def _key_help(self, key):
        if self.is_esc(key) or key == "q" or self.is_enter(key):
            self.screen = "home"
        return None

    # -- запуск проверки ----------------------------------------------------
    def start_scan(self) -> None:
        if self.running:
            return
        self.status = ""
        self.scan_error = None
        self.scan_result = None
        self.running = True
        self.frame = 0
        self.screen = "run"
        options = dict(self.opt)

        def worker() -> None:
            try:
                self.scan_result = run(
                    self.kind,
                    self.target,
                    deep=options.get("deep", False),
                    sherlock=options.get("sherlock", False),
                    maigret=options.get("maigret", False),
                    breach=options.get("breach", True),
                )
            except Exception as exc:  # noqa: BLE001 — показываем ошибку в TUI
                self.scan_error = str(exc)
            finally:
                self.running = False

        threading.Thread(target=worker, daemon=True).start()

    def finish_scan(self) -> None:
        if self.scan_error is not None:
            self.status = f"Ошибка: {self.scan_error}"
            self.toggle_mode, self.opt_index, self.screen = "run", 0, "options"
            self.scan_error = None
            return
        if self.scan_result is not None:
            self.results.append(self.scan_result)
            self.view_index = len(self.results) - 1
            self.scroll = 0
            self.screen = "result"
            self.status = "Готово. s — сохранить, r — повторить."
        self.scan_result = None


def run_tui(options: dict) -> int:
    if curses is None:
        print("Интерактивный режим недоступен: модуль curses не найден.", file=sys.stderr)
        return 2

    def _main(stdscr):
        return WatsonTUI(stdscr, options).run()

    return curses.wrapper(_main)


def self_test() -> None:
    messages = [{"id": 1, "text": "Срочно оплатите комиссию: https://example.test @helper"}]
    rep = scan_export_from_messages(messages)
    assert risk(rep)[0] == 6
    assert detect("+79991234567") == "phone"
    assert crypto_kind("0x0000000000000000000000000000000000000000") == "eth"
    assert "Примерная дата регистрации" in dict(scan_id("1973230366")["findings"])
    assert breach_kind("person@example.org") == "email"
    assert breach_kind("@some_user") == "username"
    assert breach_kind("+79991234567") == "phone"
    hostile = new_report("Тест", "<img src=x onerror=alert(1)>")
    hostile["flags"].append((3, "<script>bad()</script>"))
    hostile["flags"].append((9, "высший приоритет"))
    hostile["notes"].append("<b>note</b>")
    hostile["links"].append(("js", "javascript:alert(1)"))
    card = html_report(hostile)
    assert "<img src=x" not in card and "&lt;img src=x" in card
    assert "<script>bad()</script>" not in card
    assert "javascript:alert(1)" not in card
    assert card.index("+9") < card.index("+3")
    page = render_page([hostile, scan_id("1973230366")])
    assert "prefers-color-scheme" in page
    assert "break-inside:avoid" in page
    assert "Сводка" in page
    assert "data-paginate" in page
    assert _wcswidth("Привет") == 6
    assert _wcswidth("Ａ") == 2
    assert _wcswidth("e\u0301") == 1
    assert len(_ascii_banner("WATSON")) == 5
    assert _wrap("x" * 50, 10) == ["x" * 10] * 5
    assert all(_wcswidth(line) <= 12 for line in _wrap("слово " * 20, 12))
    assert _clip("abcdef", 3) == "abc"
    assert default_output_path("email", "a@b.com", "html").endswith(".html")
    assert "mailaccess" in SCANNERS and SCANNERS["investigate"] is scan_mailaccess
    payload = _mailaccess_payload('шум\n{"status": "complete", "findings_by_module": {}}\nхвост')
    assert payload["status"] == "complete"
    ma = new_report("Тест", "a@b.com")
    apply_mailaccess_report(ma, {
        "status": "complete",
        "exposure_score": 12,
        "risk_level": "medium",
        "findings_by_module": {
            "account_discovery": [{
                "platform": "Example",
                "url": "https://example.test/u/1",
                "confidence": "high",
                "metadata": {"username": "demo"},
            }],
            "hibp": [{"platform": "HIBP", "confidence": "high"}],
        },
    })
    labels = [label for label, _ in ma["findings"]]
    values = " ".join(value for _, value in ma["findings"])
    assert any("Example" in label for label in labels)
    assert ("MailAccess: Example", "https://example.test/u/1") in ma["links"]
    assert "hibp" in values.lower()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Watson — OSINT-триаж по открытым источникам и собственным экспортам")
    parser.add_argument("args", nargs="*", help="цель или: тип цель (tg|id|phone|email|mailaccess|user|domain|crypto|export|evidence|breach)")
    parser.add_argument("-f", "--file", help="файл целей, по одной в строке")
    parser.add_argument("--export", help="Telegram Desktop JSON-экспорт")
    parser.add_argument("--evidence", action="append", metavar="PATH", help="локальный JSON/CSV/TXT-материал расследования; можно указать несколько раз")
    parser.add_argument("--id", dest="telegram_id", help="проверить Telegram ID и оценить дату регистрации")
    parser.add_argument("--out", help="сохранить Markdown-отчёт")
    parser.add_argument("--deep", action="store_true", help="дополнительные данные Telegram через ваш Telethon-сеанс")
    parser.add_argument("--sherlock", action="store_true", help="проверить username через установленный Sherlock")
    parser.add_argument("--maigret", action="store_true", help="проверить username через установленный Maigret")
    parser.add_argument("--no-breach", action="store_true", help="не проверять email/username по breach-источникам")
    parser.add_argument("--html", help="сохранить HTML")
    parser.add_argument("--pdf", help="сохранить PDF через weasyprint")
    parser.add_argument("--json", help="сохранить JSON")
    parser.add_argument("--csv", help="сохранить CSV")
    parser.add_argument("--no-cache", action="store_true", help="удалить локальный HTTP-кэш перед запуском")
    parser.add_argument("--self-test", action="store_true", help="запустить встроенную проверку")
    parser.add_argument("--bot", action="store_true", help="запустить Watson как Telegram-бот (long polling)")
    parser.add_argument("--bot-token", help="токен Telegram-бота (или WATSON_TELEGRAM_BOT_TOKEN)")
    parser.add_argument("--tui", action="store_true", help="запустить интерактивный интерфейс (по умолчанию без аргументов)")
    parser.add_argument("--no-tui", action="store_true", help="не запускать интерактивный интерфейс")
    ns = parser.parse_args(argv)
    if ns.self_test:
        self_test()
        print("ok")
        return 0
    if ns.no_cache and CACHE_DB.exists():
        CACHE_DB.unlink()

    token = ns.bot_token or os.getenv("WATSON_TELEGRAM_BOT_TOKEN")
    has_target = bool(ns.args or ns.file or ns.export or ns.evidence or ns.telegram_id)
    launch_bot = ns.bot or (bool(token) and not has_target)
    if launch_bot and token:
        return run_telegram_bot(token, ns.deep, ns.sherlock, ns.maigret, not ns.no_breach)
    if launch_bot and not token:
        parser.error("для режима бота нужен --bot-token или WATSON_TELEGRAM_BOT_TOKEN")
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
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not targets:
        if (ns.tui or interactive) and not ns.no_tui:
            if curses is None:
                parser.error("интерактивный режим недоступен: модуль curses не найден")
            return run_tui({"deep": ns.deep, "sherlock": ns.sherlock, "maigret": ns.maigret, "breach": not ns.no_breach})
        parser.error("укажите цель, --export или --file")

    reports = []
    for index, (kind, target) in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"[{index}/{len(targets)}] {kind}: {target}", file=sys.stderr)
        try:
            reports.append(run(kind, target, ns.deep, ns.sherlock, ns.maigret, not ns.no_breach))
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
