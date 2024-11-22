#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"

int main() {
    uint8_t i;
    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f};

    uint8_t in[16];
    uint8_t out[16];

    char user_input[17];
    printf("Enter a 16-character plaintext: ");
    fgets(user_input, sizeof(user_input), stdin);

    size_t len = strlen(user_input);
    if (user_input[len - 1] == '\n') {
        user_input[len - 1] = '\0';
    }

    if (strlen(user_input) != 16) {
        printf("Error: Plaintext must be exactly 16 characters.\n");
        return 1;
    }

    memcpy(in, user_input, 16);

    uint8_t *w;
    w = aes_init(sizeof(key));
    aes_key_expansion(key, w);

    printf("Plain message:\n%s\n", user_input);

    aes_cipher(in, out, w);

    printf("Ciphered message:\n");
    for (i = 0; i < 4; i++) {
        printf("%02x %02x %02x %02x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
    }
    printf("\n");

    free(w);

    return 0;
}
