#!/usr/bin/env python3

from argparse import ArgumentParser
from collections import namedtuple
from hashlib import sha512
from secrets import choice
from typing import List

from Crypto.PublicKey import RSA


Ticket = namedtuple('Ticket', ('id', 'fr', 'to', 'amount', 'hash'))
priv_key = RSA.generate(2048)
pub_key = priv_key.publickey()

def parse_args():
    parser = ArgumentParser(
        prog='ticket_sign',
        epilog='(C) Nikolaev Vadim CS-501 2018',
        description='Реализация протокола подписи чека без разглашения id',
        usage='./main [-h|--help] [-c|--corrupt] [-n|--count NUM]',
    )
    parser.add_argument(
        '-c', '--corrupt',
        action='store_true',
        help='Сделать 1 чек с другой суммой',
    )
    parser.add_argument(
        '-n', '--count',
        type=int,
        default=5,
        help='Количество генерируемых чеков',
    )
    return parser.parse_args()


def generate_tickets(count, corrupt):
    res = []
    ids = range((1<<32) - 1)
    for _ in range(count):
        id = choice(ids)
        fr = 'Petya'
        to = 'Vanya'
        amount = 100
        hash = sha512(' '.join(str(e) for e in [id, fr, to, amount]).encode('ascii')).digest()
        res.append(Ticket(id, fr, to, amount, hash))
    if corrupt:
        bad_ticket_idx = choice(range(count))
        id = choice(ids)
        fr = 'Petya'
        to = 'Vanya'
        amount = 10000
        hash = sha512(' '.join(str(e) for e in [id, fr, to, amount]).encode('ascii')).digest()
        res[bad_ticket_idx] = Ticket(id, fr, to, amount, hash)
    return res


def check_tickets(tickets):
    # type: (List[Ticket]) -> bool, Ticket
    my_ticket_idx = choice(range(len(tickets)))
    bank_amout = None
    if my_ticket_idx == 0:
        bank_amout = tickets[1].amount
    else:
        bank_amout = tickets[0].amount
    for i in range(len(tickets)):
        if i == my_ticket_idx:
            continue
        print('Банк прочитал чек:')
        print('  ID:', tickets[i].id)
        print('  AMOUNT:', tickets[i].amount)
        if bank_amout != tickets[i].amount:
            print('Банк нам больше не верит\n')
            print('\033[1;31mНе сошлись суммы перевода, ожидалось %d, получено %d\033[0m' % (bank_amout, tickets[i].amount))
            return False, tickets[my_ticket_idx], None
        print('Степерь доверия банка выросла.\n')
    return True, tickets[my_ticket_idx], priv_key.sign(tickets[my_ticket_idx].hash, 0)[0]


def ntvdm():
    args = parse_args()
    count, corrupt = args.count, args.corrupt # type: int, bool

    tickets = generate_tickets(count, corrupt) # type: List[Ticket]
    print('Сгенерировали %s чеков' % count)
    if corrupt:
        print('\033[1;31m  1 билет скомпрометирован\033[0m', end='\n\n')

    print('Банк начал проверять чеки')
    signed, my_ticket, sign = check_tickets(tickets) # type: bool, Ticket, int
    if signed:
        print('Банк подписал наш чек:')
        print('  ID:', my_ticket.id)
        print('  FROM:', my_ticket.fr)
        print('  TO:', my_ticket.to)
        print('  AMOUNT:', my_ticket.amount)
        print('  SIGN:', sign)
        print('  VALID:', pub_key.verify(my_ticket.hash, (sign,)))
        if corrupt:
            print('\033[1;32mШалость удалась ]:->\033[0m')
    else:
        print('\033[1;31mБанк не подписал наш чек\033[0m')


if __name__ == '__main__':
    ntvdm()
