#!/usr/bin/env python3

from argparse import ArgumentParser
from hashlib import sha512
from secrets import choice


class Alice:
    def __init__(self, secret):
        if secret != 0 and secret != 1:
            raise ValueError('Excpected 0 or 1, got %s' % secret)
        self._secret = secret
        self._r1 = None
        self._r2 = None
        self._hash = None

    @property
    def r1(self):
        return self._r1

    @property
    def r2(self):
        return self._r2

    @property
    def hash(self):
        return self._hash

    @staticmethod
    def _generate_bytes(length):
        choices = range(256)
        return bytes(choice(choices) for _ in range(length))

    def corrupt_hash(self):
        bad_byte_idx = choice(range(64))
        new_byte_choices = range(256)
        new_byte = choice(new_byte_choices)
        while new_byte == self._hash[bad_byte_idx]:
            new_byte = choice(new_byte_choices)
        self._hash = self._hash[:bad_byte_idx] + bytes((new_byte,)) + self._hash[bad_byte_idx+1:]
        return bad_byte_idx

    def generate(self):
        self._r1 = self._generate_bytes(112)
        self._r2 = self._generate_bytes(104)
        self._r2 = self._r2[:-1] + bytes((self._r2[-1] | 1 if self._secret else self._r2[-1] & 0xfe,))
        self._hash = sha512(self._r1 + self._r2).digest()


class Bob:
    def __init__(self, r1, h):
        self.r1 = r1
        self.r2 = None
        self.h = h

    def get_secret(self):
        if self.r2 is None:
            return None
        return self.r2[-1] & 1

    def check_secret(self, r2):
        h = sha512(self.r1 + r2).digest()
        self.r2 = r2
        return h, self.h == h


def parse_args():
    parser = ArgumentParser(
        prog='Bit keeping',
        epilog='(C) Nikolaev Vadim CS-501 2018',
        description='Реализация протокола передачи бита на хранение',
        usage='./main [-h|--help] [-s|--secret 1|0] [-c|--corrupt]'
    )
    parser.add_argument(
        '-s', '--secret',
        type=int,
        choices=[1, 0],
        help='Передаваемый секретный бит',
        default=1,
    )
    parser.add_argument('-c', '--corrupt',
        action='store_true',
        help='Имитация злоумышленника со стороны Алисы',
        default=False,
    )
    return parser.parse_args()


def ntvdm():
    args = parse_args() # type: namedtuple
    corrupt, secret = args.corrupt, args.secret

    alice = Alice(secret)
    alice.generate() # type: bytes, bytes

    if corrupt:
        print(
            '\033[1;31mАлиса злоумышленник и передаёт неправильный хэш (испорчен'\
            ' %s байт)\033[0m' % alice.corrupt_hash(),
            end='\n\n',
        )

    print('Алиса сгенерировала секрет и передала Бобу R1 и HASH')
    print('  R1:', alice.r1)
    print('  HASH:', alice.hash.hex(), end='\n\n')

    bob = Bob(alice.r1, alice.hash)
    print('Алиса решила раскрыть секрет и отправила R2')
    print('  R2:', alice.r2, end='\n\n')

    print('Боб проверяет хэши:')
    h, valid = bob.check_secret(alice.r2) # type: bytes, bool
    print('  NEW_HASH:', h.hex(), end='\n\n')

    if valid:
        print('\033[1;32mХэши совпали, секретный бит -', bob.get_secret())
    else:
        print('\33[1;31mХэши не совпали, секрету не верим')


if __name__ == '__main__':
    ntvdm()
