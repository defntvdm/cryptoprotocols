#!/usr/bin/env python3
"""
Реализация протокола Шамира
"""

from argparse import ArgumentParser
from secrets import choice
from string import ascii_lowercase

from Crypto.Util.number import inverse, getPrime


class ShamirParticipant:
    def __init__(self):
        self.d = None
        self.e = None
        self.p = None

    def generate_key(self, p):
        """
        Генерирует ключ для участника протокола Шамира
        """
        self.p = p
        self.e = getPrime(64)
        self.d = inverse(self.e, self.p - 1)

    def encode(self, data: bytes):
        encoded: int = pow(int.from_bytes(data, 'big'), self.e, self.p)
        return encoded.to_bytes((encoded.bit_length() + 7) // 8, 'big')

    def decode(self, data: bytes):
        decoded: int = pow(int.from_bytes(data, 'big'), self.d, self.p)
        return decoded.to_bytes((decoded.bit_length() + 7) // 8, 'big')


def parse_args():
    parser = ArgumentParser(
        prog='shamir',
        epilog='(C) Nikolaev Vadim CS-501 2018',
        description='Реализация протокола Шамира с коммутативным шифром',
        usage='./main [-h|--help] [-s|--secret SECRET]'
    )
    parser.add_argument(
        '-s', '--secret',
        type=lambda x: bytes(x, 'utf-8'),
        help='Передаваемый секрет, если не задан генерируется случайным образом 40 символов'
    )
    return parser.parse_args()


def get_random_secret(length: int=40):
    return bytes(ord(choice(ascii_lowercase)) for _ in range(length))


def ntvdm():
    args = parse_args()
    if args.secret is None:
        args.secret = get_random_secret()
    alice_secret = args.secret

    print('Предполагаемый секрет:', alice_secret.decode('utf-8'), end='\n\n')

    alice = ShamirParticipant()
    alice.generate_key(getPrime(512))
    print('Параметры Алисы:')
    print('  p:', alice.p)
    print('  d:', alice.d)
    print('  e:', alice.e, end='\n\n')

    # Алиса шифрует секрет и отправляет Бобу
    x1 = alice.encode(alice_secret)
    print('x1:', x1, end='\n\n')

    # Боб генерирует себе ключи и шифрует x1
    bob = ShamirParticipant()
    bob.generate_key(alice.p)
    print('Параметры Боба:')
    print('  p:', bob.p)
    print('  d:', bob.d)
    print('  e:', bob.e, end='\n\n')
    x2 = bob.encode(x1)
    print('x2:', x2, end='\n\n')

    # Алиса декодирует x2 и отправляет Бобу
    x3 = alice.decode(x2)
    print('x3:', x3, end='\n\n')

    # Боб декодирует x3
    bob_secret = bob.decode(x3)

    print('Полученный секрет:', bob_secret.decode('utf-8'), end='\n\n')
    print('\033[1;32mСекреты совпали\033[0m' if alice_secret == bob_secret else '\033[1;31mСекреты не совпали\033[0m')


if __name__ == '__main__':
    ntvdm()