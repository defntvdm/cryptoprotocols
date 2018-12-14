#!/usr/bin/env python3

from secrets import choice
from time import time

from Crypto.Cipher.AES import AESCipher


class Cipher:
    def __init__(self, cipher: AESCipher):
        self._cipher = cipher

    @staticmethod
    def new(key: bytes):
        key = (key*7)[:16] # 16 байт повторяющихся 3-ёх байтовых последовательностей
        return Cipher(AESCipher(key))

    def encrypt(self, message):
        message = message[:len(message) - len(message) % 16]
        return self._cipher.encrypt(message)

    @staticmethod
    def brute_force(message, excpected):
        for key in range(1 << 23):
            k = (key.to_bytes(3, 'big') * 8)[:16]
            cipher = AESCipher(k)
            res = cipher.decrypt(message)
            if res == excpected:
                print('Ключ        :', k)
                print('Расшифровано:', res)
                return


def main():
    secret_message = b'Hello, my name is Vadim. Bazinga'
    key = bytes(choice(range(256)) for _ in range(3))
    key = bytes((key[0] & 0x7f,)) + key[1:]
    cipher = Cipher.new(key)
    encrypted = cipher.encrypt(secret_message)
    
    print('Начальное сообщение:', secret_message)
    print('Ключ               :', key)
    print('Закодировано       :', encrypted, end='\n\n')
    print('Начало брутфорса')
    
    start = time()
    Cipher.brute_force(encrypted, secret_message)
    res = time() - start
    
    print('Брутфорс закончен, потрачено {} секунд, или примерно {:.2f} минут'.format(int(res), res / 60))


if __name__ == '__main__':
    main()
