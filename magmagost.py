import random
import struct
import sys
import csv
import os
from typing import List, Tuple, Dict, Callable, ByteString


INPUT_FILE = 'input.txt'
OUTPUT_FILE = 'output.txt'

class KeyLengthError(RuntimeError):
    pass

class BlockLengthError(Exception):
    pass

def get_random_key() -> int:
    while (key := random.getrandbits(256)).bit_length() != 256:
        continue
    return key


def bytes_from_file(filename: str, chunksize: int = 8192):
    with open(filename, 'rb') as f:
        while chunk := f.read(chunksize):
            yield from chunk


class MagmaGost:
    key: int
    sbox: List[List[int]]
    subkeys: List[int]

    BLOCK_SIZE: int = 64
    KEY_LENGTH: int = 256
    BUFFER_SIZE: int = 1024

    def __init__(self, key: int, sbox_filepath: str) -> None:
        if key.bit_length() != MagmaGost.KEY_LENGTH:
            raise KeyLengthError(
                'Key must be 256 bits long, current one is %d bit long' % key.bit_length()
            )
        self.key = key
        self.subkeys = self.expand_key(key)
        self.sbox = self.load_sbox_from_csv(sbox_filepath)

    @staticmethod
    def expand_key(key: int) -> List[int]:
        subkeys = list()
        for i in range(8):
            subkeys.append(
                (key >> (32 * i)) & 0xffffffff
            )
        return subkeys

    def f(self, input: int, key: int):
        assert input.bit_length() <= 32, \
            'Bit length of text part must be less than or equal 32, got %d instead' % input.bit_length()

        result = 0
        sum = input ^ key
        for i in range(8):
            # замена в S-блоках
            result |= self.sbox_lookup(i, sum)
        # циклический сдвиг на 11 разрядов влево
        return ((result << 11) | (result >> 21)) & 0xffffffff

    def sbox_lookup(self, row_idx: int, sum: int):
        col_idx = (sum >> (4 * row_idx)) & 0b1111
        subs = self.sbox[row_idx][col_idx]
        return subs << (4 * row_idx)

    def split_block(self, block: int) -> Tuple[int, int]:
        return block >> (self.BLOCK_SIZE // 2), block & ((1 << (self.BLOCK_SIZE//2)) - 1)

    def encryption_round(self, left: int, right: int, round_key: int) -> Tuple[int, int]:
        return right, left ^ self.f(right, round_key)

    def decryption_round(self, left: int, right: int, round_key: int) -> Tuple[int, int]:
        return right ^ self.f(left, round_key), left

    def encrypt(self, plaintext: int) -> int:
        """ Шифрование исходного сообщения (открытого текста)
        :param int plaintext: Открытый текст для зашифрования (64 бита)
        :return Зашифрованный текст (64 бита)
        :rtype: int
        """
        if plaintext.bit_length() > 64:
            raise RuntimeError('Size of block must be less than or equal 64 bits, got %d instead' % plaintext.bit_length())

        # left, right = self.split_block(plaintext)
        left = plaintext >> 32
        right = plaintext & 0xffffffff

        for i in range(8 * 3):
            left, right = self.encryption_round(left, right, self.subkeys[i % 8])
        for i in range(8):
            left, right = self.encryption_round(left, right, self.subkeys[7 - i])

        return (left << 32) | right

    def decrypt(self, ciphertext: int):
        if ciphertext.bit_length() > 64:
            raise RuntimeError('Size of block must be less than or equal to 64 bits, got %d instead' % ciphertext.bit_length())

        left, right = self.split_block(ciphertext)

        for i in range(8):
            left, right = self.decryption_round(left, right, self.subkeys[i])
        for i in range(8 * 3):
            left, right = self.decryption_round(left, right, self.subkeys[(7-i) % 8])

        return (left << (self.BLOCK_SIZE // 2)) | right

    def encrypt_file(self, filepath: str):
        pass

    @staticmethod
    def circularshift_left(n: int, shift: int, max_bits: int = 32):
        return ((n << shift) | (n >> (max_bits - shift))) & ((1 << max_bits)-1)

    @staticmethod
    def load_sbox_from_csv(filepath: str, delimiter=',') -> List[List[int]]:
        data = list()
        try:
            with open(filepath, 'r') as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=delimiter)
                for row in csv_reader:
                    data.append([int(n) for n in row])

            # проверка на корректность структуры S-блоков
            if len(data) != 8 or not all([len(row) == 16 for row in data]):
                raise RuntimeError('The dimensions of the substitution table must be 8x16!')
            return data

        except IOError as e:
            raise RuntimeError("S-box file %s doesn't exist or isn't readable" % filepath)


def main():
    # Пример
    # Ключ, указанный в приложении к стандарту ГОСТ 34.12-15 для блочных шифров
    key = 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    # a = 0xfedcba9876543210

    text = 'hello123'
    a, = struct.unpack(
        'q',
        bytes(text, encoding='utf-8')
    )
    gost = MagmaGost(key, 'sblocks.csv')

    encrypted = gost.encrypt(a)
    decrypted = gost.decrypt(encrypted)

    assert a == decrypted, 'упс, не работает'

    print('Key (K):', hex(key))
    print('Input (P):', hex(a))
    print('E(P, K) = C =', hex(encrypted))
    print('D(C, K) = P =', hex(decrypted))

    return 0


if __name__ == '__main__':
    sys.exit(main())
