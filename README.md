# btool
A tool for creating binary files from strings and encrypting them.
Converts a string byte sequence to bytes.
Converts files of bytes to strings.

Reads from stdin or file.

Encryption/Decryption

output to stdout or file

default: reads from stdin outputs to stdin.

-f <inputfile>

-o < outfile>

-e <algorithm>

-d <algorithm>

Read from stdin and output to out.bin
btool "\x41\x41\x41\x41\x41\x41\x41\x41\x41"

Read from file encrypt with xor
btool -f test.txt  -e xor

btool -f out.bin -d xor

func str2byte

func byte2Str

func eXor

func dXor

func toStdin()

func toFile

func fromFile()

func fromStdin()
