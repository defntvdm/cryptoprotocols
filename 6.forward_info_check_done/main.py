#!/usr/bin/env python3

from argparse import ArgumentParser

from Crypto.PublicKey import RSA


KEYS_IN_PROGRESS = dict()
SECRET = None


def generate_key():
    key = RSA.generate(2048)
    pub_key = key.publickey()
    KEYS_IN_PROGRESS[pub_key.n] = key
    return pub_key


def user_sends_password(passwd, key):
    encrypted = key.encrypt(passwd, None)
    return key.n, encrypted


def check_password(enc, n):
    key = KEYS_IN_PROGRESS[n]
    passwd = key.decrypt(enc)
    return passwd, passwd == SECRET


def parse_args():
    parser = ArgumentParser(
        prog='forward_info_check',
        epilog='(C) Nikolaev Vadim CS-501 2018',
        description='Прямой способ проверки информации',
        usage='./main SECRET [-h|--help]'
    )
    parser.add_argument(
        'secret',
        type=lambda x: bytes(x, 'ascii'),
        help='Секрет, который ожидается от пользователя'
    )
    return parser.parse_args()


def main():
    global SECRET
    SECRET = parse_args().secret
    passwd = input('Введите пароль: ')
    key_for_user = generate_key()
    print()
    print('Пользователь ввёл:', passwd)
    n, user_passwd = user_sends_password(passwd.encode(), key_for_user)
    print('Пользователь отправил:')
    print('  Шифр текст:', user_passwd[0])
    print('  ID ключа  :', n, end='\n\n')
    decoded, valid = check_password(user_passwd, n)
    
    print('Сервер декодировал:', decoded)
    if valid:
        print('\033[1;32mПроверка прошла успешно\033[0m')
    else:
        print('\033[1;31mПроверка провалилась\033[0m')


if __name__ == '__main__':
    main()
