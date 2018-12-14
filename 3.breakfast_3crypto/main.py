#!/usr/bin/env python3

from argparse import ArgumentParser
from secrets import choice


class Particapant:
    def __init__(self, id: int, one: bool, two: bool):
        self.id = id
        self.one = one
        self.two = two

    def compare(self, other):
        return int(self.two != other.one)


def parse_args():
    parser = ArgumentParser(
        prog='breakfast_3crypto',
        epilog='(C) Nikolaev Vadim CS-501 2018',
        description='Реализация булева протокола',
        usage='./main [-h|--help] [-p|--payer]'
    )
    parser.add_argument(
        '-p', '--payer',
        action='store_true',
        help='Есть ли человек, который хочет заплатить'
    )
    return parser.parse_args()


def main():
    payer = parse_args().payer
    particapants = []
    for i in range(1, 4):
        val = bool(choice(range(2)))
        particapants.append(Particapant(i, val, val))
    if payer:
        payer_idx = choice(range(3))
        particapants[payer_idx].two = not particapants[payer_idx].one
    particapants.append(particapants[0])
    res = 0

    for p1, p2 in zip(particapants, particapants[1:]):
        print(p1.id, 'показывает', p2.id, '"%s"' % int(p1.two))
        print(p2.id, 'показываеь', p1.id, '"%s"' % int(p2.one))
        if p1.compare(p2):
            print('Не совпали', end='\n\n')
            res += 1
        else:
            print('Совпали', end='\n\n')
        
    if res % 2:
        print('Кто-то хочет заплатить')
    else:
        print('Никто не хочет платить')


if __name__ == '__main__':
    main()
