import hashlib
import argparse
from time import sleep

def identify_hash(hash_value):
    hash_length = len(hash_value)

     if hash_length == 32:
        return "MD5"
    elif hash_length == 40:
        return "SHA1"
    elif hash_length == 64:
        return "SHA256"
    elif hash_length == 128:
        return "SHA512"
    elif hash_length == 56:  
        return "SHA3-224"
    elif hash_length == 96:  
        return "SHA3-384"
    elif hash_length == 104:  
        return "RIPEMD-160"
    elif hash_length == 128:  
        return "Whirlpool/BLAKE2b"
    elif hash_length == 64:  
        return "BLAKE2s"
    else:
        return "[-] Tipo de hash não identificado"

def crack_password(hash_type, hash_value, wordlist_path):
    with open(wordlist_path, 'r') as f:
        for password in f.readlines():
            password = password.strip()
            hashed_password = hashlib.new(hash_type, password.encode()).hexdigest()
            
            print(f"[*] Atacando com: {password}")

            if hashed_password == hash_value:
                return password
            
    return None

def main():
    parser = argparse.ArgumentParser(description='Invencivel! O quebrador de Hash.')
    parser.add_argument('-t', '--target', required=True, help='Hash alvo')
    parser.add_argument('-w', '--wordlist', required=True, help='Caminho para a wordlist')

    args = parser.parse_args()

    hash_value = args.target
    wordlist_path = args.wordlist

    # Identificar o tipo de hash
    hash_type = identify_hash(hash_value)
    print(f"[+] Tipo de hash identificado: {hash_type}")

    password = crack_password(hash_type.lower(), hash_value, wordlist_path)
    
    if password:
        print(f"[+] Senha encontrada: {password}")
    else:
        print("[-] Senha não encontrada.")

if __name__ == '__main__':
    main()
