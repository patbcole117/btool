# btool
A tool for creating binary files.

#######################################################\
Examples:\
#######################################################\
+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+


./btool -b "\x41\x41\x41\x41\x41\x41\x41\x41" -o A.txt\
[+] Read 8 bytes from stdin.


\x41\x41\x41\x41\x41\x41\x41\x41


[+] Wrote 8 bytes to A.txt.


+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+


./btool -b $(python3 -c 'print("\x41"*8 + "\x42"*8 + "\x43"*8 + "\x44"*8 + "\x45"*8 )') -o ABCDE.txt -c 4\
[+] Read 40 bytes from stdin.


\x41\x41\x41\x41\
\x41\x41\x41\x41\
\x42\x42\x42\x42\
\x42\x42\x42\x42\
\x43\x43\x43\x43\
\x43\x43\x43\x43\
\x44\x44\x44\x44\
\x44\x44\x44\x44\
\x45\x45\x45\x45\
\x45\x45\x45\x45


[+] Wrote 40 bytes to ABCDE.txt.

+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+


./btool -b $(python3 -c 'print("A"*64 + "\x42"*64 + "C"*64)') -e aes -o ABC-AES256.txt\
[+] Read 192 bytes from stdin.

\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42
\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43
\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43
\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43
\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43

[+] Encrypted 192 bytes with AES-256. Key is saved to "a.key".\
[+] Result is 220 bytes.\
\x8f\xb2\x36\x6c\x62\xe0\xb4\xc2\x02\xb6\x20\xba\xe3\xa5\x24\x7d
\x3c\x8e\xfb\x69\xd8\xbe\xd7\x2f\xf0\xb9\x49\x6d\xb6\x58\x98\xd9
\xe2\x3b\x58\x8e\x33\x3d\xd9\xc6\x46\xad\xe8\x55\x6b\x1d\xa4\xc4
\x7a\x36\xf2\x0a\x99\xa4\x64\x6b\x85\x56\x59\x2b\xe9\x32\x5d\x7f
\xf3\xb0\x81\x17\x83\x0d\x51\xcb\xd2\x8e\xed\x41\x04\x7e\xe0\x4f
\xcf\xb7\x41\x37\xee\x0d\x75\xa7\xdd\x65\x4f\x16\xe8\x0c\x9e\xc9
\x15\xd8\x87\xea\x3b\x81\x9b\xc3\x42\xf5\xd3\x71\x3d\x1e\xd8\x0e
\xaa\x4a\x89\xa1\x32\x3b\x5a\x43\x0f\x8c\xc6\xe0\x98\xc9\x1c\x20
\x27\x40\x13\xeb\x7c\xcd\x14\x16\x95\xca\x9b\x80\x98\xc8\xe6\xa7
\x4c\x18\x5d\xc9\x70\x64\x1f\xd8\x5d\x43\x12\x0f\x67\x0a\xf0\xdb
\x6b\xc4\x81\x3d\xfe\x02\xb4\x16\x94\xcc\xdd\x9f\x25\xe6\xb2\x73
\xad\x4e\x64\x59\xaa\x64\xc3\x57\x9f\x5d\x29\x34\x89\x58\x9a\xe5
\x1f\x2c\x7a\x6e\xbd\xda\x21\x83\x82\x46\x60\x2f\x3d\x5c\x8b\x42
\x01\xb9\xf9\x5b\xd3\xc1\x8b\x5d\x0f\x7a\x0c\x0c

[+] Wrote 220 bytes to ABC-AES256.txt.


+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+


./btool -i ABC-AES256.txt -d aes -o ABC.txt\
[+] Read 220 bytes from ABC-AES256.txt.

\x9c\xe9\x43\x3d\xcf\xeb\x07\xde\x69\x03\x5b\x91\x02\xd2\x29\xc6
\xc4\x4c\x45\xac\xa6\x0d\xa4\x73\xa8\x0a\x08\x7c\x3d\x7c\xd9\x65
\xda\x76\x69\x8a\x87\xf4\x3f\xbf\x5f\xee\xc6\x45\xa6\x35\x4f\xdf
\x0b\x18\x43\x51\x4b\x4c\x10\x2f\x15\xf4\xeb\x96\x72\x61\x89\x6f
\x4a\x9c\x99\x09\x89\xdb\x45\x05\x18\xc2\xae\x34\xe9\xe0\x04\x95
\xbd\x89\xd7\xc7\xd0\x2a\xd6\xd3\x65\x4d\xa8\x44\x62\x7e\x79\x0e
\x9d\x48\x01\x6c\x53\x53\xab\xd5\x39\x45\x05\xc1\x4c\xe7\xef\x15
\x61\xb1\x0f\xdc\x42\xf5\x3b\x32\x7f\x0a\x7f\xd7\x3b\x75\x4a\x7c
\x75\x05\x49\x55\xed\xac\x4e\x7e\xad\x05\xbc\x04\xf7\x13\xab\xc9
\x93\xf7\x91\x74\xe3\x39\x7d\x87\x24\xec\xec\x8d\xa8\xc6\x70\xe2
\xfe\xca\xda\x35\x7f\x06\x46\x3a\xd2\x73\x62\x3d\xcf\x9d\xd1\x1e
\x36\x9f\xb5\x52\x1f\x42\x02\x20\xca\xb1\x0a\x2d\x80\xe8\xe3\x1d
\x55\xe2\x75\x8a\x11\x9d\xaf\xff\xa5\xd8\x55\x63\x79\xff\x35\x69
\x88\x91\x68\xfa\xb9\x6b\xe7\xf4\x4c\x45\xf2\x2c

[+] Decrypted 220 bytes with AES-256. Key used was "a.key".\
[+] Result is 192 bytes.\
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42
\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43
\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43
\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43
\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43

[+] Wrote 192 bytes to ABC.txt.


+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+
