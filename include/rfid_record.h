#pragma once
#include <stdint.h>

typedef struct __attribute__((packed)) {
    uint8_t  tag_id[8];
    uint32_t counter;   // little-endian
    uint8_t  mac[4];    // Trunc4(HMAC-SHA256)
} rfid_record_v1_t;

#define RFID_RECORD_V1_SIZE 16
