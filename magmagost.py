#!/usr/bin/env python3
import argparse
import array
import random
import enum
import struct
import codecs
import multiprocessing as mp
import sys
import csv
import os
import tqdm
import typing
from typing import IO, List, Tuple, BinaryIO, Dict, Union, Optional
from ansi_colors import Colors


class KeyLengthError(RuntimeError):
    pass


class BlockLengthError(Exception):
    pass


def get_random_key() -> int:
    while (key := random.getrandbits(256)).bit_length() != 256:
        continue
    return key


#  см. ГОСТ 34.13-2015, п. 4.1
class MagmaPaddingMode(enum.IntEnum):
    PAD_MODE_1: int = 1
    PAD_MODE_2: int = 2
    PAD_MODE_3: int = 3

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return str(self)

class MagmaGost:
    key: int
    sbox: List[List[int]]
    __subkeys: List[int]

    BLOCK_SIZE: int = 64
    BLOCK_SIZE_BYTES: int = 8
    KEY_LENGTH: int = 256
    BUFFER_SIZE: int = 1024
    PADDING_MODE: MagmaPaddingMode = MagmaPaddingMode.PAD_MODE_1

    def __init__(self, key: int, sbox_filepath: str) -> None:
        if key.bit_length() != MagmaGost.KEY_LENGTH:
            raise KeyLengthError(
                'Key must be 256 bits long, current one is %d bit long' % key.bit_length()
            )
        self.key = key
        self.__subkeys = self.expand_key(key)
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
        if input.bit_length() > 32:
            raise ValueError(
                'Bit length of text part must be less than or equal 32, got %d instead' % input.bit_length()
            )

        result = 0
        sum = input ^ key
        for i in range(8):
            # замена в S-блоках
            result |= ((self.sbox[i][(sum >> (4 * i)) & 0b1111]) << (4 * i))
        # циклический сдвиг на 11 разрядов влево
        return ((result << 11) | (result >> 21)) & 0xffffffff

    def split_block(self, block: int) -> Tuple[int, int]:
        return block >> (self.BLOCK_SIZE // 2), block & ((1 << (self.BLOCK_SIZE // 2)) - 1)

    def __encryption_round(self, left: int, right: int, round_key: int) -> Tuple[int, int]:
        return right, left ^ self.f(right, round_key)

    def __decryption_round(self, left: int, right: int, round_key: int) -> Tuple[int, int]:
        return right ^ self.f(left, round_key), left

    def encrypt_bytes(self, byte_buffer: Union[bytes, bytearray]) -> bytes:
        # распаковываем исходные 8 байтов в два unsigned int, по 4 байта каждый
        right, left = struct.unpack('@2I', byte_buffer)

        for i in range(8 * 3):
            left, right = self.__encryption_round(left, right, self.__subkeys[i % 8])
        for i in range(8):
            left, right = self.__encryption_round(left, right, self.__subkeys[7 - i])

        return struct.pack('@2I', right, left)

    def decrypt_bytes(self, byte_buffer: Union[bytes, bytearray]) -> bytes:
        right, left = struct.unpack('@2I', byte_buffer)

        for i in range(8):
            left, right = self.__decryption_round(left, right, self.__subkeys[i])
        for i in range(8 * 3):
            left, right = self.__decryption_round(left, right, self.__subkeys[(7 - i) % 8])

        return struct.pack('@2I', right, left)

    def split_into_blocks(self, data: Union[bytes, bytearray]) -> Union[bytes, bytearray]:
        for i in range(0, len(data), self.BLOCK_SIZE // 8):
            start, end = i, i + 8
            yield data[start:end]

    def encrypt_stream(self, f_in: BinaryIO, f_out: BinaryIO, buffer_size: int = 1024) -> None:
        if buffer_size % self.BLOCK_SIZE != 0:
            raise ValueError('Buffer size must be a multiple of default block size (64)!')

        pbar = tqdm.tqdm(desc='Зашифрование', total=os.stat(f_in.fileno()).st_size, dynamic_ncols=True, colour='green', leave=True)
        while data := f_in.read(buffer_size):
            out_buffer = array.array('B')
            pbar.update(buffer_size)
            for block in self.split_into_blocks(data):
                if len(block) < 8:
                    # "добиваем" блок данных незначащими нулями
                    block = block.ljust(8, b'\x00')
                out_buffer.extend(self.encrypt_bytes(block))
            out_buffer.tofile(f_out)

    def get_padding_size(self, filesize: int) -> int:
        padding_mode = self.PADDING_MODE
        if padding_mode is MagmaPaddingMode.PAD_MODE_1:
            if self.BLOCK_SIZE_BYTES - (filesize % self.BLOCK_SIZE_BYTES) == self.BLOCK_SIZE_BYTES:
                return 0
        if padding_mode is MagmaPaddingMode.PAD_MODE_3:
            if self.BLOCK_SIZE_BYTES - (filesize % self.BLOCK_SIZE_BYTES) == self.BLOCK_SIZE_BYTES:
                return 0

        return self.BLOCK_SIZE_BYTES - (filesize % self.BLOCK_SIZE_BYTES)

    def set_ecb_padding( self, f_in: BinaryIO, padding_size: int):
        if padding_size <= 0:
            return

        if self.PADDING_MODE is MagmaPaddingMode.PAD_MODE_1:
            f_in.seek(0, 2)
            f_in.write(b'\x00' * (padding_size)) # дополняем блок нулями
        if self.PADDING_MODE is MagmaPaddingMode.PAD_MODE_2:
            f_in.seek(0, 2)
            f_in.write(b'\x80') # записываем единицу в первый бит дополнения
            f_in.write(b'\x00' * padding_size) # дополняем остальное нулями
        if self.PADDING_MODE is MagmaPaddingMode.PAD_MODE_3:
            f_in.seek(0, 2)
            f_in.write(b'\x80') # записываем единицу в первый бит дополнения
            f_in.write(b'\x00' * padding_size) # дополняем остальное нулями

    def encrypt_file(self, infile: str, outfile: str, buffer_size: int = 1024):
        if not os.path.isfile(infile) \
                or (os.path.isfile(outfile) and os.path.samefile(outfile, infile)):
            raise ValueError('Input and output files must exist and not cannot be the same file')

        filesize = os.path.getsize(infile)

        # индикатор прогресса
        pbar = tqdm.tqdm(
            total=filesize,
            desc='Зашифрование:',
            leave=True,
            dynamic_ncols=True,
            colour='red'
        )

        with open(infile, 'r+b') as f_in:
            with open(outfile, 'wb') as f_out:
                out_buffer = array.array('B')
                while filesize > 0:
                    if filesize > self.BLOCK_SIZE_BYTES:
                        block = f_in.read(self.BLOCK_SIZE_BYTES)
                        out_buffer.extend(
                            self.encrypt_bytes(block)
                        )
                        filesize -= self.BLOCK_SIZE_BYTES
                        pbar.update(self.BLOCK_SIZE_BYTES)
                    else: # дополняем неполный блок
                        pad_len = self.get_padding_size(
                            os.stat(f_in.fileno()).st_size
                        )
                        self.set_ecb_padding( f_in, pad_len)

                        pad_block = f_in.read(self.BLOCK_SIZE_BYTES)

                        out_buffer.extend(
                            self.encrypt_bytes(pad_block)
                        )
                        filesize = 0
                        pbar.update(pad_len)
                out_buffer.tofile(f_out)

    def decrypt_file(self, infile: str, outfile: str, buffer_size=1024):
        if not os.path.isfile(infile) \
                or (os.path.isfile(outfile) and os.path.samefile(outfile, infile)):
            raise ValueError('Input and output files must exist and not cannot be the same file')

        filesize = os.path.getsize(infile)

        # индикатор прогресса
        pbar = tqdm.tqdm(
            total=filesize,
            desc='Расшифрование:',
            leave=True,
            dynamic_ncols=True,
            colour='green'
        )

        with open(infile, 'r+b') as f_in:
            with open(outfile, 'wb') as f_out:
                while filesize > 0:
                    if filesize > self.BLOCK_SIZE_BYTES:
                        block = f_in.read(self.BLOCK_SIZE_BYTES)
                        f_out.write(
                            self.decrypt_bytes(block)
                        )
                        filesize -= self.BLOCK_SIZE_BYTES
                        pbar.update(self.BLOCK_SIZE_BYTES)
                    else:
                        last_block = f_in.read(self.BLOCK_SIZE_BYTES)

                        f_out.write(
                            self.decrypt_bytes(last_block)
                        )
                        filesize = 0
                        pbar.update(self.BLOCK_SIZE_BYTES)



    def encrypt(self, plaintext: int) -> int:
        if plaintext.bit_length() > 64:
            raise RuntimeError(
                'Size of block must be less than or equal 64 bits, got %d instead' % plaintext.bit_length())

        left, right = self.split_block(plaintext)

        for i in range(8 * 3):
            left, right = self.__encryption_round(left, right, self.__subkeys[i % 8])
        for i in range(8):
            left, right = self.__encryption_round(left, right, self.__subkeys[7 - i])

        return (left << (self.BLOCK_SIZE // 2)) | right

    def decrypt(self, ciphertext: int):
        if ciphertext.bit_length() > 64:
            raise RuntimeError(
                'Size of block must be less than or equal to 64 bits, got %d instead' % ciphertext.bit_length())

        left, right = self.split_block(ciphertext)

        for i in range(8):
            left, right = self.__decryption_round(left, right, self.__subkeys[i])
        for i in range(8 * 3):
            left, right = self.__decryption_round(left, right, self.__subkeys[(7 - i) % 8])

        return (left << (self.BLOCK_SIZE // 2)) | right

    def read_from_console(self):
        sys.stdin.reconfigure(encoding='ascii', errors='backslashreplace')
        try:
            while True:
                user_input = input('>> ')
                data, data_len = codecs.escape_decode(user_input)
                for block in self.split_into_blocks(data):
                    if len(block) < MagmaGost.BLOCK_SIZE_BYTES:
                        block = block.ljust(self.BLOCK_SIZE_BYTES, b'\x00')

                    block = self.encrypt_bytes(block)
                    sys.stdout.write(block.hex())
                sys.stdout.write('\n')
        except KeyboardInterrupt:
            print(Colors.BOLD + 'Exiting...' + Colors.ENDC)
            return 0

    @staticmethod
    def circularshift_left(n: int, shift: int, max_bits: int = 32):
        return ((n << shift) | (n >> (max_bits - shift))) & ((1 << max_bits) - 1)

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
                raise ValueError('The dimensions of the substitution table must be 8x16!')
            return data

        except IOError as e:
            raise RuntimeError("S-box file %s doesn't exist or isn't readable" % filepath)


def main():
    argparser = argparse.ArgumentParser(
        description='Encrypt/decrypt using "Magma" symmetric block cipher'
    )

    argparser.add_argument('-k', '--key', dest='key', type=str, metavar='KEY', help='key in hexadecimal notation')
    argparser.add_argument('-i', '--input-file', dest='input', nargs='?', metavar='INFILE'
        # type=argparse.FileType('rb')
    )

    argparser.add_argument('-o', '--outfile', nargs='?', metavar='OUTFILE', dest='output'
        # type=argparse.FileType('wb'),
    )

    argparser.add_argument('-sbox', '--sbox-filepath', required=True, nargs='?', dest='sbox_filepath',
        type=str, help='path to CSV file with S-box values '
    )

    action_mode = argparser.add_mutually_exclusive_group(required=True)
    action_mode.add_argument('-e', '--encrypt', dest='encrypt', help='file to decrypt (stdin if none)', action='store_true')
    action_mode.add_argument('-d', '--decrypt', dest='decrypt', help='file to decrypt (stdout if none)', action='store_true')
    
    argparser.add_argument('--padding-mode', dest='padding_mode', help='padding mode',
        metavar='PADDING_MODE', required=False, action='store',
        type=int, choices=[int(mode.value) for mode in MagmaPaddingMode]
    )

    argparser.add_argument('--buffer-size', dest='buffer_size', action='store', nargs='?', type=int, default=8*1024)

    args = argparser.parse_args()

    if not args.key:
        while len(key := input(f'{Colors.BOLD}{Colors.UNDERLINE}Enter key:{Colors.ENDC} ')) != 64:
            print(Colors.BOLD+Colors.RED + 'Incorrect key length! Must be 64, got', len(key), Colors.ENDC)
        args.key = key

    try:
        args.key = int(args.key, 16)
    except ValueError:
        print(Colors.RED + 'Error converting key to integer!' + Colors.ENDC)
        print(Colors.BOLD + Colors.RED + 'Exiting...' + Colors.ENDC)
        return 1
    except OverflowError:
        print('Overflow occured when converting key to hexadecimal!')
        print('Exiting...')
        return 1

    try:
        magma = MagmaGost(args.key, args.sbox_filepath)
    except KeyLengthError as e:
        print(e)
        return 1

    if args.padding_mode is not None:
        magma.PADDING_MODE = MagmaPaddingMode(args.padding_mode)

    if args.input is None and args.output is None:
        magma.read_from_console()
        return 0

    if args.encrypt:
        magma.encrypt_file(args.input, args.output, args.buffer_size)
    else:
        magma.decrypt_file(args.input, args.output, args.buffer_size)

    return 0

if __name__ == '__main__':
    sys.exit(main())
