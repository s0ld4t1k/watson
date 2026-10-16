#!/usr/bin/env python3
"""
Watson - агрегатор OSINT по ОТКРЫТЫМ источникам для проверки подозрительных
контактов (Telegram-аккаунт, номер, ник, домен, крипто-кошелёк).

Не использует утёкшие базы и персональные данные третьих лиц.
Результат - эвристическая оценка риска, а не доказательство и не "пробив".

Установка:  pip install requests phonenumbers
(опционально: telethon для --deep, weasyprint для --pdf)
Примеры:
  python watson.py @some_user
  python watson.py +79991234567
  python watson.py scam-site.com --html report.html
  python watson.py 0x1234...abcd --json report.json
  python watson.py user nickname      # явно указать тип: tg|phone|user|domain|crypto
  python watson.py @some_user --deep  # + ID, возраст, общие группы (Telethon)
  python watson.py -f targets.txt --html all.html --pdf all.pdf --csv all.csv
"""
import argparse
import datetime as dt
import html
import json
import re
import socket
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import requests

UA = {"User-Agent": "Mozilla/5.0 (Watson-OSINT/0.1)"}
CACHE_DB = Path.home() / ".watson_cache.sqlite"
CACHE_TTL = 6 * 3600  # секунд


# ---------------------------------------------------------------- кэш и HTTP
def _db():
    con = sqlite3.connect(CACHE_DB)
    con.execute("CREATE TABLE IF NOT EXISTS c (url TEXT PRIMARY KEY, status INT, body TEXT, ts REAL)")
    return con


def fetch(url, ttl=CACHE_TTL, timeout=12):
    """GET с кэшем. Возвращает (status, text); status 0 при сетевой ошибке."""
    con = _db()
    row = con.execute("SELECT status, body, ts FROM c WHERE url=?", (url,)).fetchone()
    if row and time.time() - row[2] < ttl:
        con.close()
        return row[0], row[1]
    try:
        r = requests.get(url, headers=UA, timeout=timeout, allow_redirects=True)
        status, body = r.status_code, r.text
    except requests.RequestException:
        con.close()
        return 0, ""
    if status < 500:
        con.execute("REPLACE INTO c VALUES (?,?,?,?)", (url, status, body, time.time()))
        con.commit()
    con.close()
    return status, body


def fetch_json(url, **kw):
    st, body = fetch(url, **kw)
    try:
        return st, json.loads(body)
    except (ValueError, TypeError):
        return st, None


# ------------------------------------------------------------ модель отчёта
def new_report(kind, target):
    return {"type": kind, "target": target, "findings": [], "flags": [], "links": [], "notes": []}


def add(rep, label, value):
    if value not in (None, "", [], {}):
        rep["findings"].append((label, str(value)))


def flag(rep, points, reason):
    rep["flags"].append((points, reason))


def risk(rep):
    score = sum(p for p, _ in rep["flags"])
    level = "низкий" if score <= 1 else "средний" if score <= 4 else "высокий"
    return score, level


def days_ago(iso):
    try:
        d = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return (dt.datetime.now(dt.timezone.utc) - d).days
    except (ValueError, AttributeError):
        return None


# ------------------------------------------------------------------ Telegram
SCAM_WORDS = ["инвест", "заработ", "крипт", "гарант", "депозит", "вывод средств", "сигнал",
              "пассивный доход", "удалённ", "удаленн", "без вложений", "ставки", "прогноз"]
IMPERSONATION = ["support", "поддержка", "admin", "админ", "official", "менеджер", "bank", "банк",
                 "garant", "гарант", "helper", "service"]


def _meta(body, prop):
    m = re.search(r'<meta property="%s" content="([^"]*)"' % re.escape(prop), body)
    return html.unescape(m.group(1)) if m else ""


def scan_telegram(target):
    u = re.sub(r"^(https?://)?(t\.me/|telegram\.me/)?@?", "", target.strip()).split("/")[0].split("?")[0]
    rep = new_report("Telegram", "@" + u)
    st, body = fetch(f"https://t.me/{u}")
    if st != 200:
        rep["notes"].append(f"t.me вернул статус {st}, проверка не удалась")
        return rep
    title, desc = _meta(body, "og:title"), _meta(body, "og:description")
    exists = title and title != f"Telegram: Contact @{u}"
    add(rep, "Существует (эвристика)", "да" if exists else "не найден или скрыт")
    if exists:
        add(rep, "Имя", title)
        add(rep, "Описание (bio)", desc)
        extra = re.search(r'tgme_page_extra">([^<]+)', body)
        if extra:
            add(rep, "Доп. информация", html.unescape(extra.group(1)).strip())
        kind = "бот" if u.lower().endswith("bot") else "канал/группа" if extra and re.search(
            r"subscribers|members|подпис|участ", extra.group(1), re.I) else "пользователь"
        add(rep, "Тип (эвристика)", kind)
        low = f"{title} {desc}".lower()
        hits = [w for w in SCAM_WORDS if w in low]
        if hits:
            flag(rep, min(3, len(hits)), "В имени/bio характерные слова: " + ", ".join(hits))
        imp = [w for w in IMPERSONATION if w in f"{title} {u}".lower()]
        if imp:
            flag(rep, 2, "Имя/ник похож на выдачу себя за поддержку/официальное лицо: " + ", ".join(imp))
        if re.search(r"t\.me/\+|joinchat|bit\.ly|tinyurl", desc, re.I):
            flag(rep, 1, "В bio ссылки-перенаправления")
    else:
        rep["notes"].append("Аккаунт мог быть удалён, переименован или заблокирован.")
    rep["notes"].append("Telegram API не раскрывает дату создания; ID можно получить через Telethon "
                        "с вашим аккаунтом: чем больше ID, тем новее аккаунт.")
    rep["links"] += [
        ("Профиль t.me", f"https://t.me/{u}"),
        ("Поиск ника в Google", f"https://www.google.com/search?q={quote('\"' + u + '\"')}"),
        ("Поиск ника в Яндексе", f"https://yandex.ru/search/?text={quote('\"' + u + '\"')}"),
    ]
    return rep


# ------------------------------------------- Telegram: глубокая проверка (Telethon)
# Нужен ВАШ аккаунт и api_id/api_hash с https://my.telegram.org (бесплатно):
#   export WATSON_TG_API_ID=123456 ; export WATSON_TG_API_HASH=abcdef...
# При первом запуске Telethon спросит номер и код (сессия сохранится в ~/.watson.session).
# Используются только данные, которые Telegram и так показывает вам в приложении.

# ОРИЕНТИРОВОЧНЫЕ якоря "ID -> месяц создания". Оценка грубая: откалибруйте по аккаунтам
# с известной датой через файл ~/.watson_anchors.json вида [[2768409, "2013-11"], ...]
ID_ANCHORS = [
    (2_768_409, "2013-11"), (100_000_000, "2015-03"), (500_000_000, "2018-01"),
    (1_000_000_000, "2019-12"), (2_000_000_000, "2020-12"), (5_000_000_000, "2021-11"),
    (6_000_000_000, "2022-10"), (7_000_000_000, "2023-09"),
]


def load_anchors():
    p = Path.home() / ".watson_anchors.json"
    if p.exists():
        try:
            return sorted((int(i), d) for i, d in json.loads(p.read_text()))
        except (ValueError, TypeError):
            pass
    return ID_ANCHORS


def estimate_age(uid):
    """Возвращает (текст, новее_последнего_якоря)."""
    a = load_anchors()
    if uid > a[-1][0]:
        return f"новее {a[-1][1]} (выше последней калибровочной точки)", True
    for (i1, d1), (i2, d2) in zip(a, a[1:]):
        if i1 <= uid <= i2:
            return f"между {d1} и {d2}", False
    return f"старше {a[0][1]}", False


def _status(st):
    return {"UserStatusOnline": "онлайн", "UserStatusRecently": "недавно (скрыто настройками)",
            "UserStatusLastWeek": "на этой неделе (скрыто)", "UserStatusLastMonth": "в этом месяце (скрыто)",
            "UserStatusOffline": "офлайн (время открыто)",
            "UserStatusEmpty": "давно или скрыто"}.get(type(st).__name__, "неизвестно")


def deep_telegram(rep, u):
    import os
    try:
        from telethon.sync import TelegramClient
        from telethon import errors
        from telethon.tl.functions.users import GetFullUserRequest
        from telethon.tl.functions.messages import GetCommonChatsRequest
        from telethon.tl.types import User
    except ImportError:
        rep["notes"].append("Для --deep установите Telethon: pip install telethon")
        return
    api_id, api_hash = os.getenv("WATSON_TG_API_ID"), os.getenv("WATSON_TG_API_HASH")
    if not (api_id and api_hash):
        rep["notes"].append("Для --deep задайте WATSON_TG_API_ID и WATSON_TG_API_HASH (my.telegram.org).")
        return
    try:
        with TelegramClient(str(Path.home() / ".watson"), int(api_id), api_hash) as client:
            ent = client.get_entity(u)
            add(rep, "[API] ID", ent.id)
            if isinstance(ent, User):
                est, newer = estimate_age(ent.id)
                add(rep, "[API] Возраст аккаунта (по ID, грубо)", est)
                name = " ".join(x for x in (ent.first_name, ent.last_name) if x)
                add(rep, "[API] Имя", name)
                add(rep, "[API] Доп. юзернеймы", ", ".join(x.username for x in (ent.usernames or [])))
                add(rep, "[API] Бот / Premium / Verified",
                    f"{'да' if ent.bot else 'нет'} / {'да' if ent.premium else 'нет'} / {'да' if ent.verified else 'нет'}")
                add(rep, "[API] Последний визит", _status(ent.status))
                if ent.restricted:
                    add(rep, "[API] Ограничения",
                        "; ".join(r.reason for r in (ent.restriction_reason or [])) or "есть")
                full = client(GetFullUserRequest(ent)).full_user
                add(rep, "[API] Bio", full.about)
                add(rep, "[API] Фото профиля", "есть" if full.profile_photo else "нет")
                cnt = getattr(full, "common_chats_count", 0) or 0
                add(rep, "[API] Общих групп с вами", cnt)
                if cnt:
                    chats = client(GetCommonChatsRequest(user_id=ent, max_id=0, limit=50)).chats
                    add(rep, "[API] Общие группы", "; ".join(c.title for c in chats))
                if ent.scam:
                    flag(rep, 5, "Telegram сам пометил аккаунт как SCAM")
                if ent.fake:
                    flag(rep, 5, "Telegram сам пометил аккаунт как FAKE")
                if newer:
                    flag(rep, 2, "ID новее последней калибровочной точки: вероятно, свежий аккаунт")
            else:
                add(rep, "[API] Название", getattr(ent, "title", ""))
                created = getattr(ent, "date", None)
                if created:
                    add(rep, "[API] Создан(а)", str(created)[:10])
                    age = (dt.datetime.now(dt.timezone.utc) - created).days
                    if age < 30:
                        flag(rep, 2, f"Канал/группа создан(а) {age} дн. назад")
                try:
                    add(rep, "[API] Участников", client.get_participants(ent, limit=0).total)
                except Exception:
                    pass
                if getattr(ent, "scam", False) or getattr(ent, "fake", False):
                    flag(rep, 5, "Telegram пометил канал/группу как SCAM/FAKE")
    except (errors.UsernameNotOccupiedError, errors.UsernameInvalidError, ValueError):
        rep["notes"].append("[API] Юзернейм не найден или недоступен.")
    except errors.FloodWaitError as e:
        rep["notes"].append(f"[API] Лимит Telegram, подождите {e.seconds} с и не частите: риск бана аккаунта.")
    except Exception as e:  # noqa: BLE001
        rep["notes"].append(f"[API] Ошибка: {e}")


# ------------------------------------------------------------------- телефон
def scan_phone(target):
    rep = new_report("Телефон", target)
    try:
        import phonenumbers
        from phonenumbers import PhoneNumberType as T, carrier, geocoder, timezone
    except ImportError:
        rep["notes"].append("Установите библиотеку: pip install phonenumbers")
        return rep
    raw = re.sub(r"[^\d+]", "", target)
    if not raw.startswith("+"):
        raw = "+" + raw
    try:
        num = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as e:
        rep["notes"].append(f"Не удалось разобрать номер: {e}")
        return rep
    valid = phonenumbers.is_valid_number(num)
    add(rep, "Международный формат", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    add(rep, "Валиден", "да" if valid else "нет")
    add(rep, "Страна/регион", geocoder.description_for_number(num, "ru"))
    add(rep, "Оператор (по префиксу)", carrier.name_for_number(num, "ru"))
    add(rep, "Часовые пояса", ", ".join(timezone.time_zones_for_number(num)))
    ntype = phonenumbers.number_type(num)
    names = {T.MOBILE: "мобильный", T.FIXED_LINE: "стационарный", T.FIXED_LINE_OR_MOBILE: "моб./стационарный",
             T.VOIP: "VoIP", T.TOLL_FREE: "бесплатный", T.PREMIUM_RATE: "платный (premium)",
             T.UAN: "единый номер", T.PERSONAL_NUMBER: "персональный", T.UNKNOWN: "неизвестно"}
    add(rep, "Тип линии", names.get(ntype, str(ntype)))
    if not valid:
        flag(rep, 3, "Номер невалиден (не существует в плане нумерации)")
    if ntype == T.VOIP:
        flag(rep, 3, "VoIP-номер: легко получить анонимно, частый выбор мошенников")
    if ntype == T.PREMIUM_RATE:
        flag(rep, 3, "Платный номер: возможна схема со списанием денег за звонок/SMS")
    cc = num.country_code
    if cc not in (7, 375, 380, 994) and valid:
        rep["notes"].append(f"Код страны +{cc}: сверьте с тем, что собеседник говорит о себе.")
    rep["notes"].append("Оператор определяется по исходному диапазону: после переноса номера (MNP) "
                        "может отличаться. Владельца по этим данным установить нельзя.")
    q = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    plain = q.lstrip("+")
    rep["links"] += [
        ("Google: номер + мошенник", f"https://www.google.com/search?q={quote(q + ' мошенник отзывы')}"),
        ("Яндекс: номер", f"https://yandex.ru/search/?text={quote(plain)}"),
        ("Telegram по номеру (если открыт)", f"https://t.me/{q}"),
        ("WhatsApp (проверка наличия)", f"https://wa.me/{plain}"),
    ]
    return rep


# ---------------------------------------------------------------------- ник
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
}


def scan_username(target):
    u = target.strip().lstrip("@")
    rep = new_report("Никнейм", u)

    def check(item):
        name, tpl = item
        url = tpl.format(u)
        st, _ = fetch(url, timeout=8)
        return name, url, st

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(check, USER_SITES.items()))
    found = [(n, url) for n, url, st in results if st == 200]
    unsure = [n for n, _, st in results if st not in (200, 404)]
    add(rep, "Найден на", ", ".join(n for n, _ in found) or "нигде из проверенных")
    if unsure:
        add(rep, "Не удалось проверить", ", ".join(unsure))
    rep["links"] += [(f"{n}", url) for n, url in found]
    rep["notes"].append("Совпадение ника НЕ значит, что это один человек: ники часто повторяются. "
                        "Для глубокой проверки используйте Maigret (pip install maigret).")
    if not found:
        rep["notes"].append("Ник нигде не найден: свежесозданный/одноразовый ник - слабый признак риска.")
        flag(rep, 1, "Ник не встречается на открытых площадках")
    return rep


# --------------------------------------------------------------------- домен
def scan_domain(target):
    d = re.sub(r"^https?://", "", target.strip().lower()).split("/")[0].split(":")[0]
    rep = new_report("Домен", d)
    st, data = fetch_json(f"https://rdap.org/domain/{d}")
    if data and isinstance(data, dict):
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                age = days_ago(ev.get("eventDate", ""))
                add(rep, "Дата регистрации", ev.get("eventDate", "")[:10])
                if age is not None:
                    add(rep, "Возраст домена", f"{age} дн.")
                    if age < 30:
                        flag(rep, 4, f"Домену всего {age} дн.")
                    elif age < 180:
                        flag(rep, 2, f"Домен молодой ({age} дн.)")
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for item in ent.get("vcardArray", [None, []])[1]:
                    if item[0] == "fn":
                        add(rep, "Регистратор", item[3])
        add(rep, "NS", ", ".join(n.get("ldhName", "") for n in data.get("nameservers", [])))
        status = data.get("status", [])
        add(rep, "Статусы", ", ".join(status))
        if not any(e.get("eventAction") == "registration" for e in data.get("events", [])):
            rep["notes"].append("RDAP не вернул дату регистрации (зона может скрывать данные).")
    else:
        rep["notes"].append(f"RDAP недоступен для этой зоны (статус {st}). Проверьте WHOIS вручную.")
    try:
        _, _, ips = socket.gethostbyname_ex(d)
        add(rep, "IP (A-записи)", ", ".join(ips))
    except OSError:
        add(rep, "DNS", "домен не резолвится")
        flag(rep, 1, "Домен не резолвится (возможно, уже отключён)")
    st, certs = fetch_json(f"https://crt.sh/?q={d}&output=json", timeout=20)
    if isinstance(certs, list):
        names = {n for c in certs for n in c.get("name_value", "").split("\n")}
        add(rep, "Сертификатов в crt.sh", len(certs))
        sub = sorted(n for n in names if n != d)[:10]
        add(rep, "Поддомены (до 10)", ", ".join(sub))
    st, us = fetch_json(f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=5")
    if us and us.get("results"):
        add(rep, "Сканов на urlscan.io", us.get("total", len(us["results"])))
        mal = [r for r in us["results"] if r.get("verdicts", {}).get("overall", {}).get("malicious")]
        if mal:
            flag(rep, 5, f"urlscan.io: {len(mal)} из последних сканов помечены как вредоносные")
    rep["links"] += [
        ("VirusTotal", f"https://www.virustotal.com/gui/domain/{d}"),
        ("urlscan.io", f"https://urlscan.io/search/#domain:{d}"),
        ("Wayback Machine", f"https://web.archive.org/web/*/{d}"),
        ("who.is", f"https://who.is/whois/{d}"),
        ("Google: домен + отзывы", f"https://www.google.com/search?q={quote(d + ' отзывы мошенники')}"),
    ]
    return rep


# --------------------------------------------------------------------- крипто
RE_BTC = re.compile(r"^(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
RE_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
RE_TRX = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


def crypto_kind(s):
    return "btc" if RE_BTC.match(s) else "eth" if RE_ETH.match(s) else "trx" if RE_TRX.match(s) else None


def scan_crypto(target):
    a = target.strip()
    kind = crypto_kind(a)
    rep = new_report("Крипто-кошелёк", a)
    if not kind:
        rep["notes"].append("Формат не похож на BTC / ETH / TRON адрес.")
        return rep
    add(rep, "Сеть (по формату)", {"btc": "Bitcoin", "eth": "Ethereum/EVM", "trx": "TRON"}[kind])
    first = None
    if kind in ("btc", "eth"):
        chain = "bitcoin" if kind == "btc" else "ethereum"
        key = a if kind == "btc" else a.lower()
        st, data = fetch_json(f"https://api.blockchair.com/{chain}/dashboards/address/{a}")
        info = (data or {}).get("data", {}).get(key, {}).get("address") if data else None
        if info:
            div = 1e8 if kind == "btc" else 1e18
            sym = "BTC" if kind == "btc" else "ETH"
            add(rep, "Баланс", f"{float(info.get('balance', 0)) / div:.6f} {sym}")
            if kind == "btc":
                add(rep, "Всего получено", f"{float(info.get('received', 0)) / div:.6f} {sym}")
            add(rep, "Транзакций", info.get("transaction_count"))
            first = info.get("first_seen_receiving")
            add(rep, "Первое поступление", first)
            add(rep, "Последнее поступление", info.get("last_seen_receiving"))
        else:
            rep["notes"].append(f"Blockchair не вернул данные (статус {st}); возможен лимит API.")
    else:
        st, data = fetch_json(f"https://apilist.tronscanapi.com/api/accountv2?address={a}")
        if data and isinstance(data, dict):
            add(rep, "Баланс TRX", f"{float(data.get('balance', 0)) / 1e6:.2f}")
            add(rep, "Транзакций", data.get("totalTransactionCount"))
            if data.get("date_created"):
                first = dt.datetime.fromtimestamp(data["date_created"] / 1000, dt.timezone.utc).isoformat()
                add(rep, "Создан", first[:10])
        else:
            rep["notes"].append(f"Tronscan не вернул данные (статус {st}).")
    age = days_ago(first.replace(" ", "T")) if first else None
    if age is not None and age < 30:
        flag(rep, 2, f"Кошельку {age} дн.: свежий адрес")
    explorer = {"btc": f"https://www.blockchain.com/explorer/addresses/btc/{a}",
                "eth": f"https://etherscan.io/address/{a}",
                "trx": f"https://tronscan.org/#/address/{a}"}[kind]
    rep["links"] += [("Обозреватель", explorer),
                     ("Chainabuse (жалобы)", f"https://www.chainabuse.com/address/{a}"),
                     ("Breadcrumbs (граф связей)", "https://www.breadcrumbs.app/")]
    rep["notes"].append("Проверьте адрес в Chainabuse: там публикуют жалобы пострадавшие. "
                        "Для большинства переводов следите, куда уходят средства (биржи, миксеры).")
    return rep


# ------------------------------------------------------- вывод и автоопределение
def detect(t):
    s = t.strip()
    if s.startswith("@") or re.search(r"(t\.me|telegram\.me)/", s):
        return "tg"
    if crypto_kind(s):
        return "crypto"
    if re.fullmatch(r"\+?[\d\s\-()]{9,18}", s):
        return "phone"
    if re.search(r"^(https?://)?[\w.-]+\.[a-z]{2,}(/.*)?$", s, re.I):
        return "domain"
    return "user"


SCANNERS = {"tg": scan_telegram, "phone": scan_phone, "user": scan_username,
            "domain": scan_domain, "crypto": scan_crypto}


def print_report(rep):
    score, level = risk(rep)
    print(f"\n=== {rep['type']}: {rep['target']} ===")
    for k, v in rep["findings"]:
        print(f"  {k}: {v}")
    print(f"\n  Оценка риска: {level} ({score})")
    for p, r in rep["flags"]:
        print(f"   [+{p}] {r}")
    for n in rep["notes"]:
        print(f"  * {n}")
    for name, url in rep["links"]:
        print(f"  -> {name}: {url}")
    print("\n  Оценка эвристическая. Не делайте выводов о личности и не публикуйте данные.")


def html_report(rep):
    score, level = risk(rep)
    e = html.escape
    rows = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rep["findings"])
    flags = "".join(f"<li>+{p}: {e(r)}</li>" for p, r in rep["flags"]) or "<li>признаков не найдено</li>"
    notes = "".join(f"<li>{e(n)}</li>" for n in rep["notes"])
    links = "".join(f'<li><a href="{e(u)}" rel="noopener noreferrer" target="_blank">{e(n)}</a></li>'
                    for n, u in rep["links"])
    color = {"низкий": "#2e7d32", "средний": "#ef6c00", "высокий": "#c62828"}[level]
    return f"""<section class="card"><h2>{e(rep['type'])}: {e(rep['target'])}</h2>
<p class="risk" style="background:{color}">Риск: {level} ({score})</p>
<table>{rows}</table><h3>Признаки</h3><ul>{flags}</ul>
<h3>Заметки</h3><ul>{notes}</ul><h3>Ссылки для ручной проверки</h3><ul>{links}</ul></section>"""


PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Watson report</title>
<style>:root{{color-scheme:light dark;font-family:system-ui,sans-serif}}
body{{max-width:820px;margin:2rem auto;padding:0 1rem}}
.card{{border:1px solid #8884;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}}
.risk{{display:inline-block;color:#fff;padding:.2rem .7rem;border-radius:6px}}
table{{border-collapse:collapse;width:100%}}th{{text-align:left;width:34%;vertical-align:top;padding:.2rem}}
td{{padding:.2rem;word-break:break-word}}small{{opacity:.7}}</style></head><body>
<h1>Watson</h1><small>Сформирован {ts}. Только открытые источники; оценка эвристическая.</small>{body}</body></html>"""


def run(kind, target, deep=False):
    rep = SCANNERS[kind](target)
    if kind == "tg" and deep:
        deep_telegram(rep, rep["target"].lstrip("@"))
    return rep


def read_targets(path):
    """Строка файла: цель (тип определится сам) или 'тип цель'. '#' - комментарий."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if parts[0] in SCANNERS and len(parts) > 1:
            out.append((parts[0], parts[1]))
        else:
            out.append((detect(line), line))
    return out


def save_pdf(page_html, path):
    try:
        from weasyprint import HTML
    except ImportError:
        print("Для PDF: pip install weasyprint (или откройте HTML и выберите 'Печать -> PDF').")
        return
    HTML(string=page_html).write_pdf(path)
    print(f"PDF сохранён: {path}")


def save_csv(reps, path):
    import csv
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["тип", "цель", "риск", "баллы", "признаки"])
        for r in reps:
            s, lvl = risk(r)
            w.writerow([r["type"], r["target"], lvl, s, " | ".join(x for _, x in r["flags"])])
    print(f"CSV сохранён: {path}")


def main():
    ap = argparse.ArgumentParser(description="Watson - OSINT-агрегатор по открытым источникам")
    ap.add_argument("args", nargs="*", help="цель, либо: тип цель (tg|phone|user|domain|crypto)")
    ap.add_argument("-f", "--file", help="файл со списком целей (по одной в строке)")
    ap.add_argument("--deep", action="store_true", help="Telegram: доп. данные через Telethon (ваш аккаунт)")
    ap.add_argument("--html", help="сохранить отчёт в HTML")
    ap.add_argument("--pdf", help="сохранить отчёт в PDF (нужен weasyprint)")
    ap.add_argument("--json", help="сохранить отчёт в JSON")
    ap.add_argument("--csv", help="сводная таблица в CSV")
    ap.add_argument("--no-cache", action="store_true", help="очистить кэш перед запуском")
    ns = ap.parse_args()
    if ns.no_cache and CACHE_DB.exists():
        CACHE_DB.unlink()

    targets = read_targets(ns.file) if ns.file else []
    if ns.args:
        if ns.args[0] in SCANNERS and len(ns.args) > 1:
            targets.append((ns.args[0], " ".join(ns.args[1:])))
        else:
            t = " ".join(ns.args)
            targets.append((detect(t), t))
    if not targets:
        ap.error("укажите цель или --file")

    reps = []
    for n, (kind, target) in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"[{n}/{len(targets)}] {kind}: {target}", file=sys.stderr)
        try:
            reps.append(run(kind, target, ns.deep))
        except Exception as e:  # noqa: BLE001
            print(f"  ошибка: {e}", file=sys.stderr)
        if n < len(targets):
            time.sleep(2.0 if ns.deep else 0.5)  # не злим источники и Telegram

    if len(reps) > 1:
        reps.sort(key=lambda r: risk(r)[0], reverse=True)
    for r in reps:
        print_report(r)
    if len(reps) > 1:
        print("\n=== Сводка (по убыванию риска) ===")
        for r in reps:
            s, lvl = risk(r)
            print(f"  {lvl:8} ({s:2})  {r['type']}: {r['target']}")

    page = PAGE.format(ts=dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
                       body="".join(html_report(r) for r in reps))
    if ns.html:
        Path(ns.html).write_text(page, encoding="utf-8")
        print(f"\nHTML сохранён: {ns.html}")
    if ns.pdf:
        save_pdf(page, ns.pdf)
    if ns.json:
        Path(ns.json).write_text(json.dumps(reps, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON сохранён: {ns.json}")
    if ns.csv:
        save_csv(reps, ns.csv)


if __name__ == "__main__":
    sys.exit(main())
