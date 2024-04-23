Invincible - The Hash Breaker

![Alt Text](https://ntvb.tmsimg.com/assets/p19396751_b_h10_aj.jpg?w=960&h=540)




Description

Invincible is a Python tool designed to crack passwords from ZIP files, decrypt encrypted files, and find passwords from hashes.
Features

    Crack passwords from ZIP files using a wordlist
    Find passwords corresponding to a hash using a wordlist
    Decrypt files using Fernet based on the provided password

Requirements

    Python 3.x
    Libraries: hashlib, argparse, os, pyzipper, base64, time, cryptography

Usage

Run the invincible.py script with the following arguments:

bash

python3 invincible.py -t <target> -w <wordlist>

Arguments

    -t, --target: Path to the target file (hash, zip, or cripto)
    -w, --wordlist: Path to the wordlist containing passwords

Examples

Crack a password from a ZIP file:

bash

python3 invincible.py -t file.zip -w wordlist.txt

Find the password corresponding to a hash:



python3 invincible.py -t 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

Decrypt an encrypted file:


python3 invincible.py -t encrypted_file.cripto -w wordlist.txt
