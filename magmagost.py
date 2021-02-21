import random
import sys
import csv
import os
import uuid
import binascii
from typing import List, Tuple, Dict, Callable, ByteString


class KeyLengthError(RuntimeError):
    pass

class BlockLengthError(RuntimeError):
    pass

class PaddingError(RuntimeError):
    pass


def get_random_key() -> int:
    while (key := random.getrandbits(256)).bit_length() != 256:
        continue
    return key


def bytes_from_file(filename: str, chunksize: int = 655536):
    """ Покусочное чтение файла.
    Размер блока (chunk) по умолчанию - 2 байта
    """
    with open(filename, 'rb') as f:
        while chunk := f.read(chunksize):
            yield from chunk

class MagmaGost:
    key: int
    sbox: List[List[int]]
    subkeys: List[int]

    BLOCK_SIZE: int = 64
    KEY_LENGTH: int = 256

    def __init__(self, key: int, sbox_filepath: str):
        if key.bit_length() != MagmaGost.KEY_LENGTH:
            raise KeyLengthError(
                'Key must be 256 bits long, current one is %d bit long' % key.bit_length()
            )
        self.key = key

        self.subkeys = self.expand_key(key)
        self.sbox = self.load_sbox_from_csv(sbox_filepath)

    @staticmethod
    def expand_key(key: int):
        subkeys = list()
        for i in range(8):
            subkeys.append(
                (key >> (32 * i)) & 0xffffffff
            )
        return subkeys

    def f(self, input: int, key: int):
        assert input.bit_length() == 32, \
            'Bit length of text part must be 32, got %d instead' % input.bit_length()
        result = 0

        tmp = input ^ key

        for i in range(8):
            # замена в S-блоках
            result |= self.perform_sblock_substitution(i, tmp)

        # циклический сдвиг на 11 разрядов влево
        return ((result << 11) | (result >> 21)) & 0xffffffff
        # return MagmaGost.circularshift_left(result, 11, max_bits=32)

    def perform_sblock_substitution(self, row_idx: int, sum: int):
        col_idx = (sum >> (4 * row_idx)) & 0b1111
        subs = self.sbox[row_idx][col_idx]

        return subs << (4 * row_idx)

    def split_block(self, block: int):
        return block >> self.BLOCK_SIZE // 2, block & ((1 << self.BLOCK_SIZE//2) - 1)

    def encrpyption_round(self, left: int, right: int, round_key: int):
        right = right ^ self.f(right, round_key)
        return left, right

    def decryption_round(self, left: int, right: int, round_key: int):
        right = right ^ self.f(left, round_key)
        return left, right

    def encrypt(self, plaintext: int):
        if plaintext.bit_length() != 64:
            raise RuntimeError('Size of block must be 64 bits, got %d instead' % plaintext.bit_length())

        left, right = self.split_block(plaintext)

        for i in range(8 * 3):
            left, right = self.encrpyption_round(left, right, self.subkeys[i])
        for i in range(8):
            left, right = self.encrpyption_round(left, right, self.subkeys[7-i])

        return (left << 32) | right


    def decrypt(self, ciphertext: int):
        if ciphertext.bit_length() != 64:
            raise RuntimeError('Size of block must be 64 bits, got %d instead' % ciphertext.bit_length())

        left, right = self.split_block(ciphertext)

        for i in range(8):
            left, right = self.decryption_round(left, right, self.subkeys[i])
        for i in range(8 * 3):
            left, right = self.decryption_round(left, right, self.subkeys[(7-i) % 8])

        return (left << self.BLOCK_SIZE // 2) | right

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
    key = get_random_key()
    text = 0xABCDEF0987654321

    gost = MagmaGost(key, 'sblocks.csv')

    ciphertext = gost.encrypt(text)
    plaintext = gost.decrypt(ciphertext)

    assert plaintext == text, 'упс, не работает'


if __name__ == '__main__':
    sys.exit(main())
