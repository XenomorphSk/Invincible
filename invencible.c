#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <zip.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// Função para descriptografar utilizando AES (equivalente ao Fernet)
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Criando e inicializando o contexto
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Inicializando a decriptação AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    // Fornecendo o texto cifrado para ser decriptografado
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;

    // Finalizando a decriptação
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    // Limpando o contexto
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Função para tentar descriptografar o arquivo com uma senha
int try_decrypt_with_password(const char *filename, const char *password) {
    unsigned char key[32]; // Chave AES-256
    unsigned char iv[16] = {0};  // Vetor de inicialização (IV)
    unsigned char decryptedtext[1024];

    // Gerando a chave a partir da senha com SHA-256
    EVP_Digest(password, strlen(password), key, NULL, EVP_sha256(), NULL);

    FILE *enc_file = fopen(filename, "rb");
    if (!enc_file) {
        printf("[-] Não foi possível abrir o arquivo criptografado.\n");
        return 0;
    }

    unsigned char ciphertext[1024];
    int ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), enc_file);
    fclose(enc_file);

    int decrypted_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    if (decrypted_len > 0) {
        decryptedtext[decrypted_len] = '\0';
        printf("[+] Texto descriptografado: %s\n", decryptedtext);
        return 1;
    } else {
        printf("[-] Senha incorreta ou falha na decriptação.\n");
        return 0;
    }
}

/// Função para quebrar senhas de arquivos ZIP
void crack_zip_password(const char *zip_file_path, const char *wordlist_path) {
    struct zip *za;
    struct zip_file *zf;
    struct zip_stat st;
    int err;
    
    // Abrir o arquivo ZIP
    za = zip_open(zip_file_path, ZIP_CHECKCONS, &err);
    if (!za) {
        printf("[-] Não foi possível abrir o arquivo ZIP.\n");
        return;
    }

    // Abrir a wordlist
    FILE *file = fopen(wordlist_path, "r");
    if (!file) {
        printf("[-] Não foi possível abrir a wordlist.\n");
        zip_close(za);
        return;
    }

    char password[256];
    while (fgets(password, sizeof(password), file)) {
        // Removendo newline
        password[strcspn(password, "\n")] = 0;

        // Exibir a senha que está sendo tentada
        printf("[*] Tentando senha: %s\n", password);

        // Definir a senha no arquivo ZIP
        zip_set_default_password(za, password);
        
        // Tentando extrair o primeiro arquivo do ZIP
        if (zip_stat_index(za, 0, 0, &st) == 0) {
            zf = zip_fopen_index(za, 0, 0);
            if (zf) {
                // Ler o conteúdo do arquivo para garantir que a senha é correta
                char buffer[100];
                int bytes_read = zip_fread(zf, buffer, sizeof(buffer));

                if (bytes_read > 0) {
                    printf("[+] Senha correta encontrada: %s\n", password);
                    zip_fclose(zf);
                    break;
                } else {
                    // A senha não é válida se não conseguir ler o arquivo
                    printf("[-] Senha incorreta: %s\n", password);
                }
                zip_fclose(zf);
            }
        }
    }

    fclose(file);
    zip_close(za);
}



// Função para quebrar hashes
void crack_hash(const char *hash_type, const char *hash_value, const char *wordlist_path) {
    FILE *file = fopen(wordlist_path, "r");
    if (!file) {
        printf("[-] Não foi possível abrir a wordlist.\n");
        return;
    }

    char password[256];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    char hashed_password[129];

    const EVP_MD *md;
    if (strcmp(hash_type, "md5") == 0) {
        md = EVP_md5();
    } else if (strcmp(hash_type, "sha1") == 0) {
        md = EVP_sha1();
    } else if (strcmp(hash_type, "sha256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(hash_type, "sha512") == 0) {
        md = EVP_sha512();
    } else {
        printf("[-] Tipo de hash não suportado.\n");
        return;
    }

    while (fgets(password, sizeof(password), file)) {
        // Remove newline
        password[strcspn(password, "\n")] = 0;

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, password, strlen(password));
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        EVP_MD_CTX_free(mdctx);

        for (unsigned int i = 0; i < hash_len; i++) {
            sprintf(&hashed_password[i * 2], "%02x", hash[i]);
        }

        printf("[*] Tentando senha: %s\n", password);

        if (strcmp(hashed_password, hash_value) == 0) {
            printf("[+] Senha encontrada: %s\n", password);
            fclose(file);
            return;
        }
    }

    printf("[-] Senha não encontrada.\n");
    fclose(file);
}

int main(int argc, char *argv[]) {
    char *target = NULL;
    char *wordlist = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "t:w:")) != -1) {
        switch (opt) {
            case 't':
                target = optarg;
                break;
            case 'w':
                wordlist = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -t target -w wordlist\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!target || !wordlist) {
        fprintf(stderr, "Usage: %s -t target -w wordlist\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Identificando o tipo de arquivo
    if (strstr(target, ".zip")) {
        crack_zip_password(target, wordlist);
    } else if (strstr(target, ".cripto")) {
        try_decrypt_with_password(target, wordlist);
    } else {
        // Supondo que seja um hash
        char *hash_type;
        size_t hash_len = strlen(target);
        if (hash_len == 32) {
            hash_type = "md5";
        } else if (hash_len == 40) {
            hash_type = "sha1";
        } else if (hash_len == 64) {
            hash_type = "sha256";
        } else if (hash_len == 128) {
            hash_type = "sha512";
        } else {
            printf("[-] Tipo de hash não identificado.\n");
            exit(EXIT_FAILURE);
        }

        printf("[+] Tipo de hash identificado: %s\n", hash_type);
        crack_hash(hash_type, target, wordlist);
    }

    return 0;
}
