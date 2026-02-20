#pragma once
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "rfid_hal.h"

typedef enum {
  RFID_OK = 0,
  RFID_NO_CARD,
  RFID_HW_FAIL,
  RFID_AUTH_FAIL,
  RFID_READ_FAIL,
  RFID_WRITE_FAIL,
  RFID_MAC_FAIL,
  RFID_NOT_PROVISIONED,
} rfid_status_t;

typedef struct {
  uint8_t record_block;

  uint8_t key6[6];
  int use_key_b;


  uint8_t master_hmac_key[32];

// uint8_t device_id[16]; //TODO: Server/online crypto protocol
} rfid_toolbox_cfg_t

typedef struct {
  rfid_hal_t hal;
  rfid_toolbox_cfg_t cfg;
} rfid_toolbox_t;

esp_err_t rfid_toolbox_init(rfid_toolbox_t *tb, const rfid_hal_t *hal, const rfid_toolbox_cfg_t *cfg);

// What Nanda needs
rfid_status_t rfid_read_id_u32(rfid_toolbox_t *tb, uint32_t *out_id);

rfid_status_t rfid_provision_current_tag(rfid_toolbox_t *tb, const uint8_t tag_id_8[8], uint32_t initial_counter);

rfid_status_t rfid_authorize_and__update(rfid_toolbox_t *tb int *authorized);

// --- online crypto ---
//TODO: rfid_build_auth_request()
//TODO: rfid_verify_server_auth_ed25519()





