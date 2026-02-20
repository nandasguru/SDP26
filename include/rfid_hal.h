#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

// Adapter vtable: implement using RC522 driver 
typedef struct {
    void *ctx;

    // Non-blocking: return ESP_ERR_NOT_FOUND if no card
    esp_err_t (*poll_uid)(void *ctx, uint8_t *uid, size_t *uid_len);

    esp_err_t (*mifare_auth)(void *ctx, uint8_t block_addr,
                             const uint8_t key6[6],
                             const uint8_t *uid, size_t uid_len,
                             int use_key_b);

    esp_err_t (*mifare_read_block)(void *ctx, uint8_t block_addr, uint8_t out16[16]);
    esp_err_t (*mifare_write_block)(void *ctx, uint8_t block_addr, const uint8_t in16[16]);

    void (*halt)(void *ctx); 
} rfid_hal_t;
