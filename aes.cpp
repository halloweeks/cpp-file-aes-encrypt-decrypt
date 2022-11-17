#include <cstdint>
#include <fstream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <filesystem>
#include <time.h>

namespace fs = std::filesystem;

static const size_t KEY_SIZE = 256 / 8, BLOCK_SIZE = 128 / 8;

class AESBase {
protected:
    const uint8_t *key, *iv;
    EVP_CIPHER_CTX *ctx;
    AESBase(const uint8_t *key, const uint8_t *iv) : key(key), iv(iv) {
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();
    }
    ~AESBase() {
        EVP_CIPHER_CTX_free(ctx);
    }
    static void handleErrors(void) {
        ERR_print_errors_fp(stderr);
        abort();
    }
};

class Encrypt : AESBase {
public:
    Encrypt(const uint8_t *key, const uint8_t *iv) : AESBase(key, iv) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }
    int update(const char *plaintext, int plaintext_len, char *ciphertext) {
        int len;
        if (1 != EVP_EncryptUpdate(ctx, (uint8_t*)ciphertext, &len, (const uint8_t*)plaintext, plaintext_len))
            handleErrors();
        return len;
    }
    int final(char *ciphertext) {
        int len;
        if (1 != EVP_EncryptFinal_ex(ctx, (uint8_t*)ciphertext, &len))
            handleErrors();
        return len;
    }
};

class Decrypt : AESBase {
public:
    Decrypt(const uint8_t *key, const uint8_t *iv) : AESBase(key, iv) {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }
    int update(const char *ciphertext, int ciphertext_len, char *plaintext) {
        int len;
        if (1 != EVP_DecryptUpdate(ctx, (uint8_t*)plaintext, &len, (const uint8_t*)ciphertext, ciphertext_len))
            handleErrors();
        return len;
    }
    int final(char *plaintext) {
        int len;
        if (1 != EVP_DecryptFinal_ex(ctx, (uint8_t*)plaintext, &len))
            handleErrors();
        return len;
    }
};

void test_encrypt(const uint8_t *key, const char* in, const char* out) {
    std::ifstream fin(in, std::ios_base::binary);
    std::ofstream fout(out, std::ios_base::binary);
    uint8_t iv[BLOCK_SIZE];
    RAND_bytes(iv, sizeof(iv));

    char buf[1024], temp[sizeof(buf) + BLOCK_SIZE];
    Encrypt aes(key, iv);
    fout.write((char*)iv, sizeof(iv));
    while (fin) {
        fin.read(buf, sizeof(buf));
        int len = (int)fin.gcount();
        if (len <= 0)
            break;
        len = aes.update(buf, len, temp);
        fout.write(temp, len);
    }
    int len = aes.final(temp);
    fout.write(temp, len);
}

void test_decrypt(const uint8_t *key, const char* in, const char* out) {
    std::ifstream fin(in, std::ios_base::binary);
    std::ofstream fout(out, std::ios_base::binary);
    uint8_t iv[BLOCK_SIZE];
    fin.read((char*)iv, sizeof(iv));

    char buf[1024], temp[sizeof(buf) + BLOCK_SIZE];
    Decrypt aes(key, iv);
    while (fin) {
        fin.read(buf, sizeof(buf));
        int len = (int)fin.gcount();
        if (len <= 0)
            break;
        len = aes.update(buf, len, temp);
        fout.write(temp, len);
    }
    int len = aes.final(temp);
    fout.write(temp, len);
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		printf("Usage ./aes input.file output.file -d or -e\n");
		return -1;
	}
	
	/* clock_t clock(void) returns the number of clock ticks 
	   elapsed since the program was launched.To get the number  
           of seconds used by the CPU, you will need to divide by  
           CLOCKS_PER_SEC.where CLOCKS_PER_SEC is 1000000 on typical 
           32 bit system.  */
	clock_t start, end; 
	
	// Recording the starting clock tick.
	start = clock(); 
	
	
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    uint8_t key[KEY_SIZE] = { 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2 };
    
    if (!fs::exists(argv[1])) {
    	printf("Input file %s not found\n", argv[1]);
        return -1;
    }
    
    if (fs::is_directory(argv[1])) {
    	printf("%s is not a file\n", argv[1]);
        return -1;
    }
    
    
    if (strcmp(argv[3], "-e") == 0) {
    	test_encrypt(key, argv[1], argv[2]);
    } else if (strcmp(argv[3], "-d") == 0) {
    	test_decrypt(key, argv[1], argv[2]);
    } else {
    	printf("Invalid option\n");
        return -1;
    }
    
    // Recording the end clock tick. 
	end = clock();
    
	// Calculating total time taken by the program. 
	double time_taken = (double)(end - start) / (double)(CLOCKS_PER_SEC); 
    
	// print process time"
	printf("[TIME] PROCESS COMPLETE IN %f\n", time_taken);
    
    return 0;
}