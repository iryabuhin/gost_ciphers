# Реализация шифра "Магма" (ГОСТ 34.12-15)
Длина ключа - 256 бит (32 байта).
Длина блока - 64 бита (8 байт).
S-блоки замены определены в `sblocks.csv`.

Если файл с входными/выходными данными не указан, будет использоваться стандартный ввод/вывод соответственно.

Если ключ не был в явном виде передан команде в опции `-k` (`--key`), пользователю будет предложено ввести ключ в консоль с клавиатуры (в шестнадцатеричном формате).

```bash
$ ./magmagost.py -h
usage: magmagost.py [-h] [-k KEY] [-i [INFILE]] [-o [OUTFILE]] -sbox [SBOX_FILEPATH] (-e | -d) [--buffer-size [BUFFER_SIZE]]

Encrypt/decrypt using "Magma" symmetric block cipher

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     key in hexadecimal notation
  -i [INFILE], --input-file [INFILE]
  -o [OUTFILE], --outfile [OUTFILE]
  -sbox [SBOX_FILEPATH], --sbox-filepath [SBOX_FILEPATH]
                        path to CSV file with S-box values
  -e, --encrypt         file to decrypt (stdin if none)
  -d, --decrypt         file to decrypt (stdout if none)
  --buffer-size [BUFFER_SIZE]


```