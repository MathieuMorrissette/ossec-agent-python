// this is unclean code to figure out how ossec agents communicate
// gcc SendMsg.c -o sendmsg -lcrypto -g -lz  to compile
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define TEST_STRING_1 "Hello World!"
#define TEST_STRING_2 "Test hello \n test \t test \r World\n"
#define BUFFER_LENGTH 200
#define OS_ENCRYPT 1
#define OS_MAXSTR 6144
#define OS_SIZE_128     128
#define OS_HEADER_SIZE  OS_SIZE_128  
typedef char os_md5[33];

static unsigned int global_count = 0;
static unsigned int local_count  = 0;

static unsigned int evt_count = 0;
static unsigned int rcv_count = 0;
static size_t c_orig_size = 0;
static size_t c_comp_size = 0;


static time_t saved_time = 0;

unsigned int _s_comp_print = 0;



void randombytes(void *ptr, size_t length)
{
    char failed = 0;

    static int fh = -1;
    ssize_t ret;

    if (fh < 0 && (fh = open("/dev/urandom", O_RDONLY | O_CLOEXEC), fh < 0 && (fh = open("/dev/random", O_RDONLY | O_CLOEXEC), fh < 0))) {
        failed = 1;
    } else {
        ret = read(fh, ptr, length);

        if (ret < 0 || (size_t)ret != length) {
            failed = 1;
        }
    }


    if (failed) {
    }
}


void srandom_init(void)
{
    unsigned int seed;
    randombytes(&seed, sizeof seed);
    srandom(seed);
}

int os_random(void) {
	int myrandom;
	randombytes(&myrandom, sizeof(myrandom));
	return myrandom % RAND_MAX;
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

unsigned long int os_zlib_compress(const char *src, char *dst,
                                   unsigned long int src_size,
                                   unsigned long int dst_size)
{
    if (compress2((Bytef *)dst,
                  &dst_size,
                  (const Bytef *)src,
                  src_size,
                  Z_BEST_COMPRESSION) == Z_OK) {
        dst[dst_size] = '\0';
        return (dst_size);
    }

    return (0);
}

unsigned long int os_zlib_uncompress(const char *src, char *dst,
                                     unsigned long int src_size,
                                     unsigned long int dst_size)
{
    int res = uncompress((Bytef *)dst,
                   &dst_size,
                   (const Bytef *)src,
                   src_size);
    
    if ( res == Z_OK) {
        dst[dst_size] = '\0';
        return (dst_size);
    }

    return (0);
}



typedef unsigned char uchar;


int OS_AES_Str(const char *input, char *output, const char *charkey,
              long size, short int action)
{
    static unsigned char *iv = (unsigned char *)"FEDCBA0987654321";

    if(action == OS_ENCRYPT)
    {
        return encrypt_AES((const uchar *)input, (int)size,(uchar *)charkey, iv,(uchar *)output);
    }
    else
    {
        return decrypt_AES((const uchar *)input, (int)size,(uchar *)charkey, iv,(uchar *)output);
    }
}

int encrypt_AES(const unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
  {
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
        goto end;
    }

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        goto end;
    }

	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        goto end;
    }

	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ciphertext_len = 0;
        goto end;
    }

	ciphertext_len += len;

end:
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int decrypt_AES(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
  {
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
        goto end;
    }

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        goto end;
    }

	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        goto end;
    }

	plaintext_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        plaintext_len = 0;
        goto end;
    }

	plaintext_len += len;

end:
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}


int doEncryptByMethod(const char *input, char *output, const char *charkey,
    long size, short int action,int method)
{

    printf("Will encrypt compressed data :\n");
    BIO_dump_fp (stdout, input, size);

    return OS_AES_Str(input, output,
        charkey,
        size,
        action);
}

int OS_MD5_Str(const char *str, ssize_t length, os_md5 output)
{
    unsigned char digest[16];

    int n;

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, (const unsigned char *)str, length < 0 ? (unsigned)strlen(str) : (unsigned)length);
    MD5_Final(digest, &ctx);

    output[32] = '\0';
    for (n = 0; n < 16; n++) {
        snprintf(output, 3, "%02x", digest[n]);
        output += 2;
    }

    return (0);
}


size_t CreateSecMSG(char *encryptionkey, const char *msg, size_t msg_length, char *msg_encrypted, char *agent_id)
{
    size_t bfsize;
    size_t length;
    unsigned long int cmp_size;
    u_int16_t rand1;
    char _tmpmsg[OS_MAXSTR + 2];
    char _finmsg[OS_MAXSTR + 2];
    char crypto_token[6] = {0};
    unsigned long crypto_length = 0;
    int crypto_method = 0;
    os_md5 md5sum;
    time_t curr_time;

    /* Check for invalid msg sizes */
    if ((msg_length > (OS_MAXSTR - OS_HEADER_SIZE)) || (msg_length < 1)) {
        curr_time = time(0);
        if (curr_time - saved_time > 3600) {
            // Incorrect message size
            saved_time = curr_time;
        }

        // EncSize invalid
        return (0);
    }

    memcpy(crypto_token,"#AES:",5);

    /* Random number, take only 5 chars ~= 2^16=65536*/
    rand1 = (u_int16_t) os_random();

    _tmpmsg[OS_MAXSTR + 1] = '\0';
    _finmsg[OS_MAXSTR + 1] = '\0';
    msg_encrypted[OS_MAXSTR] = '\0';

    /* Increase local and global counters */
    if (local_count >= 9997) {
        local_count = 0;
        global_count++;
    }
    local_count++;

    length = snprintf(_tmpmsg, OS_MAXSTR, "%05hu%010u:%04u:", rand1, global_count, local_count);
    memcpy(_tmpmsg + length, msg, msg_length);
    length += msg_length;

    /* Generate MD5 of the unencrypted string */
    OS_MD5_Str(_tmpmsg, length, md5sum);

    /* Generate final msg to be compressed: <md5sum><_tmpmsg> */
    strcpy(_finmsg, md5sum);
    memcpy(_finmsg + 32, _tmpmsg, length);
    length += 32;

    /* Compress the message
     * We assign the first 8 bytes for padding
     */
    cmp_size = os_zlib_compress(_finmsg, _tmpmsg + 8, length, OS_MAXSTR - 12);
    if (!cmp_size) {
        return (0);
    }
    cmp_size++;

    /* Pad the message (needs to be div by 8) */
    bfsize = 8 - (cmp_size % 8);
    if (bfsize == 8) {
        bfsize = 0;
    }

    _tmpmsg[0] = '!';
    _tmpmsg[1] = '!';
    _tmpmsg[2] = '!';
    _tmpmsg[3] = '!';
    _tmpmsg[4] = '!';
    _tmpmsg[5] = '!';
    _tmpmsg[6] = '!';
    _tmpmsg[7] = '!';

    cmp_size += bfsize;

    /* Get average sizes */
    c_orig_size += length;
    c_comp_size += cmp_size;
    if (evt_count > _s_comp_print) {
        evt_count = 0;
        c_orig_size = 0;
        c_comp_size = 0;
    }
    evt_count++;


    length = snprintf(msg_encrypted, 16, "!%s!%s", agent_id,crypto_token);

    /* Encrypt everything */
    crypto_length = doEncryptByMethod(_tmpmsg + (7 - bfsize), msg_encrypted + length,
        encryptionkey,
        (long) cmp_size,
        OS_ENCRYPT,crypto_method);


    if(cmp_size < crypto_length)
        cmp_size = crypto_length;

    return (cmp_size + length);
}



int test_success_compress_string() {

    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);


    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, i1, BUFFER_LENGTH);

    return 1;
}


// to compile gcc SendMsg.c -o sendmsg -lcrypto -g
int main (void)
{
    srandom_init();
    test_success_compress_string();
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)""; // Key here

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"FEDCA0987654321";

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    char *msg = "1:ossec:ossec: Agent started: 'Somecomputer->any'.";
    char *agentid = "184";

    char cryptmsg[OS_MAXSTR + 1];

    ssize_t msg_size;

    msg_size = CreateSecMSG(key,msg, strlen(msg), cryptmsg, agentid);


    printf("Encrypted text is:\n");
    BIO_dump_fp (stdout, cryptmsg, msg_size);
    return;
    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[256];
    char ciphertext_2[1024];

    /* Buffer for the decrypted text */
    char decryptedtext[1024];
    char decompressedtext[4096];

    memset(ciphertext_2, '\0', 1024);
    memset(decryptedtext, '\0', 1024);
    memset(decompressedtext, '\0', 4096);

    int decryptedtext_len, ciphertext_len;
    unsigned long int decompressedtext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (char *)ciphertext, ciphertext_len);


    ciphertext_len = 112;
    memcpy(ciphertext_2,"", ciphertext_len); // add some payload here
    decryptedtext_len = decrypt(ciphertext_2, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    
    
    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    BIO_dump_fp (stdout, (char *)decryptedtext, (decryptedtext_len));

    /*int exclamation_count = 0;

    while(decryptedtext[exclamation_count] == '!')
    {
        exclamation_count = exclamation_count + 1;
    }

    unsigned char padding_removed[(decryptedtext_len)];

    for (int i = exclamation_count; i <= decryptedtext_len; i++)
    {
        padding_removed[i-exclamation_count] = decryptedtext[i];
    }*/

    char* cleartext = (char *)decryptedtext;

    if (cleartext[0] == '!') { // it is compressed
        cleartext[decryptedtext_len] = '\0'; // string terminator
        cleartext++; // increase pointer
        decryptedtext_len--; // decrease buffer size

        // remove padding
        while (*cleartext == '!') {
            cleartext++;
            decryptedtext_len--;
        }

        printf("Decrypted without padding text is:\n");
        BIO_dump_fp (stdout, cleartext, decryptedtext_len);

        decompressedtext_len = os_zlib_uncompress(cleartext, decompressedtext, decryptedtext_len + 1, 4096);

    }




    /* Show the decompressed text */
    printf("Decompressed text is:\n");
    printf("%s\n", (char*)decompressedtext);

    return 0;
}


