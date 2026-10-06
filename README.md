# Watson

Объединённый скрипт для локального анализа Telegram-экспортов и проверки открытых индикаторов: username, телефон, домен и крипто-адрес.

```sh
python3 watson.py --self-test
python3 watson.py --export /path/to/result.json --html report.html --csv report.csv
python3 watson.py @some_user --deep
python3 watson.py -f targets.txt --html all.html --csv all.csv
```

Опционально: `pip install phonenumbers` для телефонов, `pip install telethon` для `--deep`, `pip install weasyprint` для PDF. Для `--deep` нужны `WATSON_TG_API_ID` и `WATSON_TG_API_HASH` с `my.telegram.org`; Telethon использует ваш аккаунт и сохранит локальную сессию.

Возраст Telegram по ID — грубая оценка. Якоря можно откалибровать в `~/.watson_anchors.json`.

Скрипт не использует утечки, закрытые базы или deanonymization. Все результаты эвристические: совпадение ника, телефона или открытого профиля не доказывает личность или мошенничество.
