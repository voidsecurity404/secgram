# SecGram

**SecGram** — неофициальный клиент Telegram на основе [Telegram Desktop](https://github.com/telegramdesktop/tdesktop) с инструментами безопасности для специалистов SOC / CERT / ИБ и удобствами для обычных пользователей.

> SecGram не связан с Telegram FZ-LLC. Используется официальный Telegram API со своими `api_id` / `api_hash`.

## Установка

Готовые сборки — на странице [Releases](../../releases).

### Windows (10/11, x64)
1. Скачайте `SecGram-<версия>-windows-x64-portable.zip`.
2. Распакуйте в любую папку и запустите `SecGram.exe`.

Данные хранятся рядом с программой (папка `TelegramForcePortable`) и не смешиваются с официальным Telegram.

### Ubuntu / Debian / Linux Mint
```bash
sudo apt install ./secgram_<версия>_amd64.deb
secgram
```

### Red Hat / Fedora / Rocky / AlmaLinux
```bash
sudo dnf install ./secgram-<версия>-1.x86_64.rpm
secgram
```

### Arch Linux / Manjaro
```bash
git clone https://github.com/voidsecurity404/secgram && cd secgram/packaging/arch
makepkg -si
```

### Любой другой Linux (glibc ≥ 2.28)
```bash
tar xf SecGram-<версия>-linux-x86_64.tar.xz
./SecGram/install.sh          # для текущего пользователя
sudo ./SecGram/install.sh     # для всей системы (/opt/secgram)
```

Данные SecGram на Linux: `~/.local/share/SecGram/`.

### Android
В разработке — отдельный проект на основе Telegram для Android.

## Возможности

Все настройки: меню **☰ → «Безопасность SecGram»**. Инструменты для сообщения: правая кнопка мыши → **SecGram**.

**Защита аккаунта**
- Окно при входе с нового устройства с кнопкой «Это не я — завершить».
- Защита кода входа: предупреждение при попытке отправить/переслать код Telegram, автоочистка буфера обмена.
- Аудит безопасности: 2FA, почта восстановления, старые сеансы, приватность номера, код-пароль.
- Кнопка паники `Ctrl+Alt+P`.

**Ссылки**
- Проверка каждой ссылки: гомоглифы, тайпсквоттинг брендов (Telegram, банки, кошельки), IP-адреса, `user@host`, сокращатели, бесплатные хостинги и туннели, открытые редиректы, `.onion`, скачивание `.exe/.apk`.
- Базы фишинга OpenPhish и Phishing Army (проверка локально).
- RDAP (возраст домена) и TLS-сертификат, раскрытие цепочки редиректов — по запросу.
- Удаление трекеров (`utm_*`, `fbclid`, `gclid`…), свои белые/чёрные списки доменов.

**Файлы**
- RTLO, двойные расширения, подмена типа по сигнатуре, макросы.
- Анализ APK (разрешения, банковские трояны, упаковщики), ZIP (Zip Slip, пароли, исполняемые внутри), PDF (JavaScript, /Launch, ссылки), PE (подпись, упаковщики, энтропия, опасные API), VBA-макросы (распаковка MS-OVBA).
- SHA-256/SHA-1/MD5, поиск по хешу в VirusTotal (файл не загружается), ClamAV, YARA, запуск в песочнице firejail.
- Запрет запуска программ, отключение автозагрузки опасных файлов.

**Расследования**
- Информация и ID сообщения, отправителя, пересылки; история имён; личные заметки.
- Извлечение IOC (IP, домены, URL, хеши, CVE, MITRE ATT&CK, кошельки BTC/ETH/TON…), обезвреживание (`hxxps[://]`), экспорт JSON/CSV/STIX 2.1/MISP/TheHive, ссылки на VirusTotal, AbuseIPDB, Shodan, urlscan и др.
- Экспорт доказательств: JSON + HTML-отчёт + медиа + SHA-256 манифест, журнал цепочки хранения.
- Список наблюдения (слова, домены, IP, regex) по всем чатам, сбор IOC из каналов, regex-поиск, декодер Base64/Hex/JWT.
- Детектор мошенничества (RU/UZ/EN), предупреждения о ссылках от незнакомцев, подмене контактов и добавлении в группы.

**Конфиденциальность**
- Удалённые и изменённые сообщения остаются в чате с пометкой и временем (видно только вам), в том числе после перезапуска; журнал шифруется AES-256-GCM.
- Ghost-режим: без отметок о прочтении (во всех или выбранных чатах), без «печатает…», оффлайн, незаметный просмотр историй и голосовых.
- Удаление EXIF/GPS из фото и видео, ссылки без превью, скрытие своего номера.

## Сборка из исходников (Linux)

```bash
git clone --recursive https://github.com/voidsecurity404/secgram && cd secgram
# зависимости как у Telegram Desktop: см. docs/building-linux.md
cd Telegram && ./configure.sh -D TDESKTOP_API_ID=<id> -D TDESKTOP_API_HASH=<hash> \
  -D DESKTOP_APP_DISABLE_AUTOUPDATE=ON && cmake --build ../out --config Release
```

`api_id` / `api_hash` получите на https://my.telegram.org.

Автоматические сборки: `.github/workflows/linux.yml`, `.github/workflows/windows.yml` (запуск по тегу `v*`; нужны секреты репозитория `API_ID` и `API_HASH`).

## O'zbekcha qisqacha

SecGram — kiberxavfsizlik mutaxassislari va oddiy foydalanuvchilar uchun himoya vositalari qo'shilgan Telegram Desktop. Windows uchun zip arxivni oching va `SecGram.exe` ni ishga tushiring; Ubuntu uchun `.deb`, RedHat uchun `.rpm`, Arch uchun `packaging/arch/PKGBUILD`. Sozlamalar: ☰ → «Безопасность SecGram».

## Лицензия

GPLv3 с исключением OpenSSL, как и Telegram Desktop — см. [LICENSE](LICENSE) и [LEGAL](LEGAL).
