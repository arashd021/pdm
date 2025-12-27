#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <unistd.h>

#define PLAINTEXT_SIZE 16

// AES encryption key (128-bit for simplicity)
unsigned char key[] = {
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30
};

// Thread function for AES encryption
void *aes_encrypt_thread(void *arg) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    unsigned char plaintext[PLAINTEXT_SIZE] = {0};  // Fixed plaintext
    unsigned char ciphertext[PLAINTEXT_SIZE];

    // Perform encryption in a loop
    while (1) {
        AES_encrypt(plaintext, ciphertext, &aes_key);
        // usleep(1000);
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <number_of_threads>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int num_threads = atoi(argv[1]);
    if (num_threads <= 0) {
        fprintf(stderr, "Number of threads should be greater than 0\n");
        exit(EXIT_FAILURE);
    }

    // Array to hold thread IDs
    pthread_t threads[num_threads];

    // Create threads
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, aes_encrypt_thread, NULL) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for threads to finish (they won't in this example)
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
