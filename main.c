#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes.h"

// Function to calculate padded size
size_t calculate_padded_size(size_t original_size) {
    size_t remainder = original_size % 16;
    return remainder == 0 ? original_size : original_size + (16 - remainder);
}

// Function to apply PKCS#7 padding
void apply_pkcs7_padding(uint8_t *data, size_t original_size, size_t padded_size) {
    uint8_t padding_value = padded_size - original_size;
    for (size_t i = original_size; i < padded_size; i++) {
        data[i] = padding_value;
    }
}

int main() {
    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    char user_input[1024]; // Allow large input for testing
    printf("Enter plaintext : ");
    fgets(user_input, sizeof(user_input), stdin);

    // Remove trailing newline if present
    size_t original_size = strlen(user_input);
    if (user_input[original_size - 1] == '\n') {
        user_input[original_size - 1] = '\0';
        original_size--;
    }

    size_t padded_size = calculate_padded_size(original_size);
    uint8_t *in = calloc(padded_size, 1);
    uint8_t *out = calloc(padded_size, 1);

    if (!in || !out) {
        printf("Memory allocation failed.\n");
        return 1;
    }

    memcpy(in, user_input, original_size);
    apply_pkcs7_padding(in, original_size, padded_size);

    uint8_t *w = aes_init(sizeof(key));
    aes_key_expansion(key, w);

    printf("Plain message:\n%s\n", user_input);

    // Encrypt each 16-byte block
    for (size_t i = 0; i < padded_size; i += 16) {
        aes_cipher(in + i, out + i, w);
    }

    printf("Ciphered message:\n");
    for (size_t i = 0; i < padded_size; i++) {
        printf("%02x ", out[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    printf("\n");

    free(in);
    free(out);
    free(w);

    return 0;
}
