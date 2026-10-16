#!/usr/bin/env python3
"""Проверка СВОИХ данных на presence в известных утечках.

Источники:
  - Have I Been Pwned (email) — требует бесплатный API-ключ: https://haveibeenpwned.com/API/Key
  - Have I Been Pwned Pwned Passwords (k-anonymity) — без ключа
"""

import hashlib
import sys
import urllib.request
import urllib.error
import json
import getpass

HIBP_EMAIL_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
HIBP_PWD_URL = "https://api.pwnedpasswords.com/range/{}"
UA = "breach-check-self/1.0"


def pwned_password(password: str) -> int | None:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"{HIBP_PWD_URL}{prefix}",
        headers={"User-Agent": UA, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
    except (urllib.error.URLError, TimeoutError):
        return None
    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def check_email(email: str, api_key: str) -> list[str] | str:
    req = urllib.request.Request(
        HIBP_EMAIL_URL.format(email),
        headers={"User-Agent": UA, "hibp-api-key": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            return [b["Name"] for b in data]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        if e.code == 401:
            return "HIBP: неверный или отсутствующий API-ключ"
        if e.code == 429:
            return "HIBP: rate limit, подожди минуту"
        return f"HIBP: HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError):
        return "HIBP: сеть недоступна"


def main() -> None:
    print("== Проверка пароля (Pwned Passwords, без ключа) ==")
    pwd = getpass.getpass("Пароль (ввод невидим): ")
    if pwd:
        n = pwned_password(pwd)
        if n is None:
            print("  сеть недоступна")
        elif n == 0:
            print("  не найден в утечках — ок")
        else:
            print(f"  НАЙДЕН в {n} утечках — срочно смени везде")

    print("\n== Проверка email (HIBP, нужен API-ключ) ==")
    print("  ключ: https://haveibeenpwned.com/API/Key (бесплатный)")
    key = getpass.getpass("HIBP API-ключ (или Enter, пропустить): ").strip()
    if not key:
        print("  без ключа email-проверка пропущена")
        return

    emails = [e.strip() for e in input("Email через запятую: ").split(",") if e.strip()]
    for em in emails:
        res = check_email(em, key)
        if isinstance(res, str):
            print(f"  {em}: {res}")
        elif not res:
            print(f"  {em}: не найден в утечках")
        else:
            print(f"  {em}: УТЕЧКИ -> {', '.join(res)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
