#!/usr/bin/env python3

from argparse import ArgumentParser
from getpass import getpass

from Crypto.Cipher.AES import AESCipher


def parse_args():
    parser = ArgumentParser(
        prog='secret_in_code',
        epilog='(C) Nikolaev Vadim CS-501 2018',
        description='Реализация булева протокола',
        usage='./main [-h|--help] [-p|--payer]'
    )
    parser.add_argument(
        '-s', '--secret',
        type=lambda x: x.lower(),
        help='Секретная фраза',
    )
    return parser.parse_args()


def key_repeater(key):
    while True:
        for b in key:
            yield b


def encrypt_xor(key, phrase):
    return bytes(a^b for a, b in zip(phrase, key_repeater(key)))


def encrypt_aes(key, phrase):
    return AESCipher(key).encrypt(phrase)


def decodestring(s):
    a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    res = ''
    for c in s:
        res += bin(a.index(c))[2:].rjust(6, '0')
    res = res.ljust(len(res) + len(res) % 8, '0')
    resi = int(res, 2)
    return memoryview(resi.to_bytes((resi.bit_length() + 7) // 8, 'big'))


def check_secret(secret):
    nothing_secret_here = 'bWVuaHViY2trYmtxb2hsdWJkaGdramdp'\
                          'bXNsZHFkZ3BrcGNjb3VoZnNscWpubG1t'\
                          'bmtocGlra2dwbGZubnFpbGZiZHFtcWx0'\
                          'cWpmbXFoanNzcG1ib3NsbXVsb291Zmpq'\
                          'Y2N1cWZubWpjcW5maWlrZm1pcWJ0dXNt'\
                          'c2JxcWhpdW9wZnJobmZtdXFrb2NpYmNr'\
                          'bmJtaG9pcWhpcWJxcXBxZmtsbGtxc3Vo'\
                          'dXFxbHFxdWZnbm5rbHV0dGtmZnV0bG5x'\
                          'ZnBiZnNkdGJmbHFxbGpwbHNnbGNzbGZi'\
                          'bWhpbHBkaHVsbnVub3FwcHNzYmhxaWl0'\
                          'bmRwbGJqY2NoZmRoZnBvY3FoZ2ptZHF0'\
                          'aGZtY2ZmY2xzc3V0aXFmZGhqc3N1ZnVx'\
                          'bWZmZHFzbXFocW1vZnVsb2Rua2txY2dt'\
                          'anRwdXBtdGZwaXV1bWZxcGNoaWZsdHFj'\
                          'Z25rc2pna2RvdWhvZmdoaWtnanNsbWpm'\
                          'YnRxYmlzbmNiZHFjc2dibWNuc2txam5i'\
                          'bGdxaXBnbGhsaW5qZnFxb2tpdHVjdGJn'\
                          'ZGRwbmNqZmRxdXFzb2dma2hxY2ZubWdt'\
                          'bmZuZmdraHNqaWlxZGhvZGRxb2Jna2l1'\
                          'anV1c2ZsbmtjanVtbXFnY3RjanBncWhj'\
                          'aGtmZ2lodXB1bGNwcGttbWZob2hsY2Nr'\
                          'ZnRjY21oc2JsY2Rqa21pcQ'
    nothing = decodestring(nothing_secret_here)
    st = 0
    try:
        for c in secret:
            f = ord(c) + 0x9f
            f %= 256
            l = nothing[26*st:]
            st = l[f] - 97
        return (len(secret) * 20) % 41 == st
    except:
        return False


def main():
    secret = parse_args().secret
    try:
        key = getpass('Введите ключ: ').encode('utf-8')
        if not key:
            print('Нужен ключ')
            exit(1)
    except KeyboardInterrupt:
        exit(1)
    except:
        print('Не получилось перевести ключ в байты')
        exit(1)
    try:
        phrase = input('Введите шифруемый текст: ').encode('utf-8')
        if not phrase:
            print('Нужен текст для шифрования')
            exit(1)
    except KeyboardInterrupt:
        exit(1)
    except:
        print('Не получилось перевести текст в байты')
        exit(1)
    key = (key * 16)[:16]
    phrase = (phrase * 16)[:16 + len(phrase) - len(phrase) % 16]
    if check_secret(secret):
        print('XOR:', encrypt_xor(key, phrase))
    else:
        print('AES:', encrypt_aes(key, phrase))


if __name__ == '__main__':
    main()
