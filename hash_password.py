import bcrypt
hashed = bcrypt.hashpw(b"123456", bcrypt.gensalt())
print(hashed.decode())