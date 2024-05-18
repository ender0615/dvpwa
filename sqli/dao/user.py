from hashlib import scrypt
from os import urandom
from base64 import b64encode, b64decode
from typing import NamedTuple, Optional

from aiopg import Connection

class User(NamedTuple):
    id: int
    first_name: str
    middle_name: Optional[str]
    last_name: str
    username: str
    pwd_hash: str
    is_admin: bool

    @classmethod
    def from_raw(cls, raw: tuple):
        return cls(*raw) if raw else None

    @staticmethod
    async def get(conn: Connection, id_: int):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE id = %s',
                (id_,),
            )
            return User.from_raw(await cur.fetchone())

    @staticmethod
    async def get_by_username(conn: Connection, username: str):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE username = %s',
                (username,),
            )
            return User.from_raw(await cur.fetchone())

    def check_password(self, password: str):
        salt, hashed_password = self.pwd_hash.split('$')
        salt = b64decode(salt)
        hashed_input_password = scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, maxmem=0, dklen=64)
        return hashed_input_password == b64decode(hashed_password)

    @staticmethod
    def hash_password(password: str) -> str:
        salt = urandom(16)
        hashed_password = scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, maxmem=0, dklen=64)
        return f"{b64encode(salt).decode('utf-8')}${b64encode(hashed_password).decode('utf-8')}"
