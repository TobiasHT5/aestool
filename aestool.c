
// Advanced Encrytpyion Algorithm Implementation
// Author: Higenyi Tobias Thomas
// Date: 16th.May.2026
// Purpose: Cryptology Course Work


/* How to use this program
 * You can run this program as a commandline tool.
 * For help, run aestool -h to get the help menu.
 * If you're just receiving the source code without the executable,
 * make sure to compile it before use.
 * You can compile it using any modern c compiler such as gcc or clang
*/

#include "aestool.h"

void print_help(char *program_name) {

    printf("=========================================\n");
    printf("         --- AESTOOL --- \n");
    printf("=========================================\n\n");

    printf("Usage:\n\n");

    printf("  Encrypt text:\n");
    printf("    %s encrypt <key> <message>\n\n", program_name);

    printf("  Decrypt text:\n");
    printf("    %s decrypt <key> <encrypted_hex>\n\n", program_name);

    printf("Options:\n");
    printf("  --help, -h      Show this help menu\n\n");

    printf("Examples:\n\n");

    printf("  Encrypt:\n");
    printf("    %s encrypt mykey \"Hello World\"\n\n", program_name);

    printf("  Decrypt:\n");
    printf("    %s decrypt mykey a1b2c3d4\n\n", program_name);
}

void xor_block(uint8_t *a, uint8_t *b) {
    for(int i = 0; i < 16; i++)
        a[i] ^= b[i];
}

void sub_bytes(uint8_t *state) {
    for(int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

void inv_sub_bytes(uint8_t *state) {
    for(int i = 0; i < 16; i++)
        state[i] = rsbox[state[i]];
}

void shift_rows(uint8_t *s) {

    uint8_t t[16];

    t[0]=s[0]; t[1]=s[5]; t[2]=s[10]; t[3]=s[15];
    t[4]=s[4]; t[5]=s[9]; t[6]=s[14]; t[7]=s[3];
    t[8]=s[8]; t[9]=s[13]; t[10]=s[2]; t[11]=s[7];
    t[12]=s[12]; t[13]=s[1]; t[14]=s[6]; t[15]=s[11];

    memcpy(s, t, 16);
}

void inv_shift_rows(uint8_t *s) {

    uint8_t t[16];

    t[0]=s[0]; t[1]=s[13]; t[2]=s[10]; t[3]=s[7];
    t[4]=s[4]; t[5]=s[1]; t[6]=s[14]; t[7]=s[11];
    t[8]=s[8]; t[9]=s[5]; t[10]=s[2]; t[11]=s[15];
    t[12]=s[12]; t[13]=s[9]; t[14]=s[6]; t[15]=s[3];

    memcpy(s, t, 16);
}

void aes_encrypt_block(uint8_t *block, uint8_t *key) {

    xor_block(block, key);

    for(int round = 0; round < 9; round++) {

        sub_bytes(block);
        shift_rows(block);
        xor_block(block, key);
    }

    sub_bytes(block);
    shift_rows(block);
    xor_block(block, key);
}

void aes_decrypt_block(uint8_t *block, uint8_t *key) {

    xor_block(block, key);

    for(int round = 0; round < 9; round++) {

        inv_shift_rows(block);
        inv_sub_bytes(block);
        xor_block(block, key);
    }

    inv_shift_rows(block);
    inv_sub_bytes(block);
    xor_block(block, key);
}

void print_hex(uint8_t *data, int len) {

    for(int i = 0; i < len; i++)
        printf("%02x", data[i]);

    printf("\n");
}

int hex_to_bytes(char *hex, uint8_t *out) {

    int len = strlen(hex);

    for(int i = 0; i < len / 2; i++)
        sscanf(hex + (2 * i), "%2hhx", &out[i]);

    return len / 2;
}

int pad_buffer(uint8_t *buffer, int len) {

    int pad = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);

    for(int i = 0; i < pad; i++)
        buffer[len + i] = pad;

    return len + pad;
}

int unpad_buffer(uint8_t *buffer, int len) {

    int pad = buffer[len - 1];

    return len - pad;
}

int main(int argc, char *argv[]) {

    /*
        No arguments
    */
    if(argc == 1) {

        printf("\n");
        printf("Welcome to AESTOOL\n");
        printf("-------------------\n\n");

        print_help(argv[0]);

        return 0;
    }

    /*
        Help menu
    */
    if(strcmp(argv[1], "--help") == 0 ||
       strcmp(argv[1], "-h") == 0) {

        print_help(argv[0]);

        return 0;
    }

    /*
        Validate arguments
    */
    if(argc < 4) {

        printf("Error: Missing arguments.\n\n");

        print_help(argv[0]);

        return 1;
    }

    /*
        Prepare key
    */
    uint8_t key[16] = {0};

    strncpy((char*)key, argv[2], 16);

    /*
        Encrypt mode
    */
    if(strcmp(argv[1], "encrypt") == 0) {

        uint8_t buffer[MAX_BUFFER_SIZE] = {0};

        int len = strlen(argv[3]);

        memcpy(buffer, argv[3], len);

        len = pad_buffer(buffer, len);

        for(int i = 0; i < len; i += 16)
            aes_encrypt_block(buffer + i, key);

        printf("Encrypted Message:\n");
        print_hex(buffer, len);
    }

    /*
        Decrypt mode
    */
    else if(strcmp(argv[1], "decrypt") == 0) {

        uint8_t buffer[MAX_BUFFER_SIZE] = {0};

        int len = hex_to_bytes(argv[3], buffer);

        for(int i = 0; i < len; i += 16)
            aes_decrypt_block(buffer + i, key);

        len = unpad_buffer(buffer, len);

        buffer[len] = '\0';

        printf("Decrypted Message:\n");
        printf("%s\n", buffer);
    }

    /*
        Invalid mode
    */
    else {

        printf("Error: Invalid mode '%s'\n\n", argv[1]);

        print_help(argv[0]);

        return 1;
    }

    return 0;
}