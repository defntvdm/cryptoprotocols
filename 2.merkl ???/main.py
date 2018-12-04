#!/usr/bin/env python3

from gost21847_89 import GOST, brute_force

def ntvdm():
    secret = b'Just test this GOST IMPLEMENTATION'
    gost = GOST.create(b'Hello, Kitty!')
    chipher = gost.encrypt(secret)
    print('ШТ:', chipher)
    brute_force(chipher, secret)
    print('ОТ:', gost.decrypt(chipher))


if __name__ == '__main__':
    ntvdm()