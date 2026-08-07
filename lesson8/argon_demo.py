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
