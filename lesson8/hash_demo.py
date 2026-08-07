import bcrypt


password = b"my_secret_password"


salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password, salt)


print("Сіль:", salt)
print("Хеш:", hashed)


password_to_check = b"my_secret_password"
if bcrypt.checkpw(password_to_check, hashed):
    print("Пароль співпадає")
    print(bcrypt.hashpw(password_to_check,salt))
else:
    print("Пароль НЕ співпадає")


wrong_password = b"wrong_password"
if bcrypt.checkpw(wrong_password, hashed):
    print("Пароль співпадає")
else:
    print("Пароль НЕ співпадає")
    print(bcrypt.hashpw(wrong_password,salt))
