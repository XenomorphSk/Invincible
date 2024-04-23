import hashlib
import argparse
import os
import pyzipper
import base64

from time import sleep
from cryptography.fernet import Fernet

def identify_type(file_path):
    if file_path.endswith('.zip'):
        return 'zip'
    elif file_path.endswith('.cripto'):
        return 'cripto'
    else:
        return 'hash'

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
        return "[-] Tipo não identificado"

def try_decrypt_with_password(cripto_file_path, password):
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    fernet = Fernet(key)

    try:
        with open(cripto_file_path, 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)
        return True, decrypted
    except Exception as e:
        return False, str(e)


def crack_zip_password(zip_file_path, wordlist_path):
    with open(wordlist_path, 'rb') as f:
        for line in f:
            password = line.decode('latin1').strip()
            print(f"[*] Tentando senha: {password}")
            
            try:
                with pyzipper.AESZipFile(zip_file_path, 'r') as zip_file:
                    zip_file.pwd = password.encode('utf-8')
                    zip_file.extractall()
                    print("[+] Senha correta encontrada!")
                    return password
            
            except pyzipper.ZipException as e:
                if "Bad password" in str(e):
                    continue
                elif "Not a zip file" in str(e):
                    print("[-] O arquivo ZIP está corrompido.")
                    break
                else:
                    print(f"[-] Erro inesperado: {e}")
                    continue



def crack_hash(hash_type, hash_value, wordlist_path):
    with open(wordlist_path, 'rb') as f:
        for line in f:
            password = line.decode('latin1').strip()
            hashed_password = hashlib.new(hash_type, password.encode('utf-8')).hexdigest()
            
            print(f"[*] Atacando com: {password}")

            if hashed_password == hash_value:
                return password
            
            sleep(0.01)  

    return None

def main():
    
    print(''' 
         _____ _   _ _   _ _____ _   _ _____ ___________ _      _____ 
        |_   _| \ | | | | |_   _| \ | /  __ \_   _| ___ \ |    |  ___|
          | | |  \| | | | | | | |  \| | /  \/ | | | |_/ / |    | |__  
          | | | . ` | | | | | | | . ` | |     | | | ___ \ |    |  __| 
         _| |_| |\  \ \_/ /_| |_| |\  | \__/\_| |_| |_/ / |____| |___ 
         \___/\_| \_/\___/ \___/\_| \_/\____/\___/\____/\_____/\____/ 
                                                                      
        by: Kyr1o5 ''')

    parser = argparse.ArgumentParser(description='Invencivel! O quebrador de Hash.')
    parser.add_argument('-t', '--target', required=True, help='Arquivo alvo (hash, zip ou cripto)')
    parser.add_argument('-w', '--wordlist', required=True, help='Caminho para a wordlist')

    args = parser.parse_args()

    file_type = identify_type(args.target)
    wordlist_path = args.wordlist

    if file_type == 'zip':
        password = crack_zip_password(args.target, wordlist_path)
        if password:
            print(f"[+] Senha ZIP encontrada: {password}")
        else:
            print("[-] Senha ZIP não encontrada.")

    elif file_type == 'hash':
        hash_value = args.target
        hash_type = identify_hash(hash_value)
        print(f"[+] Tipo de hash identificado: {hash_type}")
        password = crack_hash(hash_type.lower(), hash_value, wordlist_path)
        if password:
            print(f"[+] Senha encontrada: {password}")
        else:
            print("[-] Senha não encontrada.")

    elif file_type == 'cripto':
        success, decrypted_text = try_decrypt_with_password(args.target, wordlist_path)
        if success:
            print(f"[+] Texto descriptografado: {decrypted_text.decode('utf-8')}")
        else:
            print("[-] Senha incorreta ou descriptografia falhou.")
    else:
        print("[-] Tipo de arquivo não suportado.")


if __name__ == '__main__':
    main()
