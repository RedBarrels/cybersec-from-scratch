# Урок 8. Практична криптографія: OpenSSL та Python

Практичне заняття курсу «Кібербезпека з нуля»: живе демо в терміналі з OpenSSL,
після якого ті самі ідеї (хешування паролів, автентифіковане шифрування)
переносяться в робочий Python-код.

## Файли уроку

- [`hash_demo.py`](./hash_demo.py) — хешування пароля через `bcrypt`
- [`argon_demo.py`](./argon_demo.py) — хешування пароля через `argon2id`

## Встановлення залежностей

Для прикладів на Python знадобляться бібліотеки `bcrypt`, `argon2-cffi` та
`cryptography`. Бажано ставити їх у віртуальне середовище, а не глобально:

```bash
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
```

Встановлення конкретно `bcrypt` та `argon2-cffi` (пакет `argon2-cffi` дає
модуль `argon2`, який імпортується в `argon_demo.py`):

```bash
pip install bcrypt
pip install argon2-cffi
```

Або одним рядком разом із `cryptography` (потрібна для AES-GCM у розділі 10.3):

```bash
pip install bcrypt argon2-cffi cryptography
```

Перевірити, що все встановилось:

```bash
python3 -c "import bcrypt, argon2; print('OK')"
```

## Практична демонстрація: OpenSSL

⏱ **Таймінг:** 20 хвилин живого демо. Ідеально — hands-on: студенти повторюють
команди у своїх терміналах. OpenSSL встановлений всюди: Linux, macOS, WSL.
Перед парою перевірте версію: `openssl version` (потрібна 3.x).

Коментуйте кожну команду до натискання Enter: що робимо, що очікуємо побачити.
Файли створюйте в окремій теці: `mkdir crypto-lab && cd crypto-lab`.

### 9.1. Генерація RSA та Ed25519 ключів

```bash
# Класичний спосіб: приватний ключ RSA 2048 біт
openssl genrsa -out private.pem 2048

# Сучасний спосіб (OpenSSL 3.x, рекомендовано 3072+ біт)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem

# Ed25519 — сучасний стандарт для підписів (SSH, Git)
openssl genpkey -algorithm ED25519 -out ed_private.pem

# Витяг публічного ключа з приватного
openssl rsa -in private.pem -pubout -out public.pem
```

**Що прокоментувати:** відкрийте `private.pem` через `cat` — покажіть
PEM-формат (Base64 між `BEGIN`/`END` маркерами). Наголосіть: приватний ключ —
найцінніший файл у цій лабораторії, у реальному житті він отримує права `600`
і ніколи не потрапляє в git. Публічний ключ ми «витягуємо» з приватного —
пара пов'язана математично, зворотний напрямок неможливий. Порівняйте
розміри: RSA-3072 ключ проти крихітного Ed25519 — наочна перевага
еліптичних кривих.

### 9.2. Асиметричне шифрування та розшифровування

```bash
echo "Таємне повідомлення для уроку 7" > message.txt

# Шифрування публічним ключем (з безпечним OAEP padding)
openssl pkeyutl -encrypt -pubin -inkey public.pem \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -in message.txt -out encrypted.bin

# Спроба прочитати шифротекст
cat encrypted.bin        # бінарне сміття — так і має бути

# Розшифровування приватним ключем
openssl pkeyutl -decrypt -inkey private.pem \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -in encrypted.bin -out decrypted.txt
cat decrypted.txt        # оригінальний текст повернувся
```

**Що прокоментувати:** OAEP — рандомізований padding: зашифруйте той самий
файл двічі і покажіть через `xxd`, що шифротексти різні (захист від атак на
детермінованість; старий PKCS#1 v1.5 padding вразливий до атаки
Блайхенбахера 1998 року, яка досі періодично «воскресає» під іменами ROBOT і
DROWN). Потім спробуйте зашифрувати файл на 1 КБ — отримаєте помилку
«data too large for key size». Це жива ілюстрація тези з блоку 3: RSA не для
даних, RSA для ключів.

### 9.3. Обчислення хешів

```bash
# SHA-256 хеш файлу
sha256sum message.txt
# macOS: shasum -a 256 message.txt

# Лавинний ефект наживо
echo -n "password" | sha256sum
echo -n "Password" | sha256sum   # 1 біт різниці — інший всесвіт

# Хеш великого файлу рахується миттєво
dd if=/dev/urandom of=big.bin bs=1M count=500 2>/dev/null
time sha256sum big.bin
```

### 9.4. Цифровий підпис

```bash
# Підписання файлу приватним ключем
openssl dgst -sha256 -sign private.pem \
    -out signature.bin message.txt

# Верифікація підпису публічним ключем
openssl dgst -sha256 -verify public.pem \
    -signature signature.bin message.txt
# Verified OK

# А тепер — головний фокус уроку: змінюємо ОДИН символ
sed -i 's/7/8/' message.txt
openssl dgst -sha256 -verify public.pem \
    -signature signature.bin message.txt
# Verification failure
```

Це кульмінація демо — обіграйте її. Документ змінили на один символ — і
підпис миттєво «зламався». Саме так ваш браузер ловить підроблені
сертифікати, ОС — модифіковані драйвери, а Git — переписану історію. Дайте
студентам самим повернути символ назад і побачити `Verified OK` знову.

### 9.5. Симетричне шифрування файлу (AES-256)

```bash
# Шифрування з паролем (PBKDF2, 600 000 ітерацій — рекомендація OWASP)
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
  -in message.txt -out message.enc

# Розшифровування
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -in message.enc -out message_decrypted.txt

# Спробуйте розшифрувати з НЕПРАВИЛЬНИМ паролем — bad decrypt
```

⚠️ **Важливо:** `openssl enc` не підтримує режим GCM — тому в демо CBC. Для
authenticated encryption (AEAD) в реальному коді використовуйте бібліотеки —
приклад `AESGCM` на Python у наступному блоці. І поясніть роль PBKDF2 тут:
людський пароль «розтягується» у повноцінний 256-бітний ключ через 600 тисяч
ітерацій хешування — місток до теми KDF з блоку 4.

### 9.6. Перевірка TLS-з'єднання

```bash
# Підключення та перегляд сертифіката і параметрів TLS 1.3
openssl s_client -connect example.com:443 -tls1_3 </dev/null

# Що показати у виводі: Certificate chain (ланцюжок довіри),
# Protocol: TLSv1.3, Cipher: TLS_AES_256_GCM_SHA384

# Термін дії, суб'єкт та видавець сертифіката
echo | openssl s_client -connect example.com:443 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer
```

Гарне доповнення: прогоніть той самий домен через ssllabs.com — покажіть
оцінку конфігурації A/A+ і що саме її знижує на інших сайтах (старі
протоколи, слабкі шифронабори).

## 10. Практика: Python — bcrypt, Argon2, AES-GCM

⏱ **Таймінг:** 15 хвилин. Це прямий місток до робочого коду: саме ці три
сніпети студенти скопіюють у свої проєкти.

Встановлення:

```bash
pip install bcrypt argon2-cffi cryptography
```

### 10.1. Хешування паролів: bcrypt

Файл: [`hash_demo.py`](./hash_demo.py)

```python
import bcrypt

password = b"my_secret_password"

# Генерація солі та хешу (cost factor 12 => 2^12 = 4096 раундів)
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)
print("Сіль:", salt)
print("Хеш:", hashed)

# Перевірка правильного пароля
print(bcrypt.checkpw(b"my_secret_password", hashed))  # True

# Перевірка неправильного пароля
print(bcrypt.checkpw(b"wrong_password", hashed))      # False
```

**Що прокоментувати:** запустіть двічі — хеші різні (нова сіль щоразу), але
`checkpw` працює, бо сіль зашита в сам рядок хешу. Заміряйте час: підніміть
`rounds` з 12 до 15 і покажіть, як росте затримка — це і є та сама «навмисна
повільність». І нагадайте про ліміт 72 байти:
`bcrypt.hashpw(b"A"*72 + b"tail", salt) == bcrypt.hashpw(b"A"*72 + b"other", salt)`
— усе після 72-го байта ігнорується. Привіт, Okta.

### 10.2. Хешування паролів: Argon2id (рекомендовано)

Файл: [`argon_demo.py`](./argon_demo.py)

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()  # Argon2id за замовчуванням (m=64 MiB, t=3, p=4)

hash = ph.hash("my_secret_password")
print(hash)  # $argon2id$v=19$m=65536,t=3,p=4$...

try:
    ph.verify(hash, "my_secret_password")
    print("Пароль співпадає")
except VerifyMismatchError:
    print("Пароль НЕ співпадає")

# Прозоре оновлення параметрів з часом:
if ph.check_needs_rehash(hash):
    hash = ph.hash("my_secret_password")
```

**Що прокоментувати:** розберіть рядок хешу по частинах — версія, m/t/p
параметри, сіль, дайджест: усе self-contained. Окремо покажіть
`check_needs_rehash`: через 5 років залізо стане швидшим, ви піднімете
параметри в коді — і хеші користувачів прозоро оновляться при наступному
вході, без жодного «скиньте пароль». Argon2id — перший вибір OWASP, і на
нових проєктах питання «bcrypt чи Argon2» вже не стоїть.

### 10.3. Authenticated encryption: AES-GCM

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

nonce = os.urandom(12)   # 96 біт; НОВИЙ для кожного повідомлення!
plaintext = "Дані уроку 7".encode()

ciphertext = aesgcm.encrypt(nonce, plaintext, None)
print(aesgcm.decrypt(nonce, ciphertext, None).decode())

# Демонстрація захисту цілісності: псуємо один байт
broken = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
aesgcm.decrypt(nonce, broken, None)   # InvalidTag — підміну помічено!
```

**Що прокоментувати:** модуль недарма називається `hazmat` — «небезпечні
матеріали»: бібліотека чесно попереджає, що на цьому рівні легко помилитися.
Зверніть увагу на `os.urandom` для nonce (криптографічно стійкий генератор —
ніколи не `random.random`!) і на фінал: один зіпсований байт — і `decrypt`
кидає `InvalidTag` замість тихо повернути сміття. Це та сама автентифікація з
абревіатури AEAD, і саме тому GCM, а не «голий» CBC.
