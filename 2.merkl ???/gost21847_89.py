class GOST:
    sbox = (
        (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
        (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
        (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
        (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
        (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
        (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
        (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
        (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12)
    )

    def __init__(self, key):
        self.key = key

    @classmethod
    def create(cls, key):
        if not isinstance(key, bytes):
            raise TypeError('Expected bytes')
        key = int.from_bytes(key, 'big')
        return cls([(key >> (16 * i)) & 0xffff for i in range(2)])

    @classmethod
    def _xor_expression(cls, part, key):
        tmp = (part + key) % (1 << 16)
        result = 0
        for i in range(8):
            result |= ((cls.sbox[i][(tmp >> (4 * i)) & 0b1111]) << (4 * i))
        result = ((result >> (16 - 7)) | (result << 7)) & 0xffff
        return result

    @classmethod
    def _enc_round(cls, ileft, iright, key):
        oleft = iright
        oright = ileft ^ cls._xor_expression(iright, key)
        return oleft, oright

    def _encrypt_block(self, block):
        if not isinstance(block, bytes):
            raise TypeError('Expected bytes')
        block = int.from_bytes(block, 'big')
        left = block >> 16
        right = block & 0xffff

        for i in range(6):
            left, right = self._enc_round(
                left, right, self.key[i % 2]
            )

        for i in range(2):
            left, right = self._enc_round(
                left, right, self.key[1 - i]
            )

        result = (left << 16) | right
        return result.to_bytes((result.bit_length() + 7) // 8, 'big')

    def encrypt(self, data):
        if not isinstance(data, bytes):
            raise TypeError('Expected bytes')
        result = []
        for i in range(0, len(data), 4):
            result.append(self._encrypt_block(data[i:i+4]))
        return b''.join(result)

    @classmethod
    def _dec_round(cls, ileft, iright, key):
        oright = ileft
        oleft = iright ^ cls._xor_expression(ileft, key)
        return oleft, oright

    def _decrypt_block(self, block):
        if not isinstance(block, bytes):
            raise TypeError('Expected bytes')
        block = int.from_bytes(block, 'big')
        left = block >> 16
        right = block & 0xffff

        for i in range(2):
            left, right = self._dec_round(left, right, self.key[i])

        for i in range(6):
            left, right = self._dec_round(left, right, self.key[(1 - i) % 2])

        result = (left << 16) | right
        return result.to_bytes((result.bit_length() + 7) // 8, 'big')

    def decrypt(self, data):
        if not isinstance(data, bytes):
            raise TypeError('Expected bytes')
        result = []
        for i in range(0, len(data), 4):
            result.append(self._decrypt_block(data[i:i+4]))
        return b''.join(result)

def brute_force(data, expected):
    for k in range(1<<32):
        key = k.to_bytes((k.bit_length() + 7) // 8, 'big')
        gost = GOST.create(key)
        decr = gost.decrypt(data)
        if decr == expected:
            print(key, ':', decr)
