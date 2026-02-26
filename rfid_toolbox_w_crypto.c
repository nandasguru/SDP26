#include "rfid_toolbox.h"
#include "rfid_record.h"
#include <string.h>
#include "mbedtls/md.h"

static void hmac_trunc4(const uint8_t key[32], const uint8_t tag_id[8], uint32_t counter, uint8_t out4[4])
{
    uint8_t msg[12];
    memcpy(msg, tag_id, 8);
    msg[8]  = (uint8_t)(counter & 0xFF);
    msg[9]  = (uint8_t)((counter >> 8) & 0xFF);
    msg[10] = (uint8_t)((counter >> 16) & 0xFF);
    msg[11] = (uint8_t)((counter >> 24) & 0xFF);

    uint8_t full[32];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(info, key, 32, msg, sizeof(msg), full);
    memcpy(out4, full, 4);
}

esp_err_t rfid_toolbox_init(rfid_toolbox_t *tb, const rfid_hal_t *hal, const rfid_toolbox_cfg_t *cfg)
{
    if (!tb || !hal || !cfg) return ESP_ERR_INVALID_ARG;
    tb->hal = *hal;
    tb->cfg = *cfg;
    if (tb->cfg.record_block == 0) tb->cfg.record_block = 4;
    return ESP_OK;
}

// if UID is 4b, big endian to u32, if not, CRC32 to output the UID bytes
static uint32_t crc32_ieee(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

rfid_status_t rfid_read_id_u32(rfid_toolbox_t *tb, uint32_t *out_id)
{
    if (!tb || !out_id) return RFID_HW_FAIL;

    uint8_t uid[10];
    size_t uid_len = sizeof(uid);
    esp_err_t err = tb->hal.poll_uid(tb->hal.ctx, uid, &uid_len);
    if (err == ESP_ERR_NOT_FOUND) return RFID_NO_CARD;
    if (err != ESP_OK) return RFID_HW_FAIL;

    if (uid_len == 4) {
        *out_id = ((uint32_t)uid[0] << 24) | ((uint32_t)uid[1] << 16) |
                  ((uint32_t)uid[2] << 8)  | ((uint32_t)uid[3]);
    } else {
        *out_id = crc32_ieee(uid, uid_len);
    }

    if (tb->hal.halt) tb->hal.halt(tb->hal.ctx);
    return RFID_OK;
}

static rfid_status_t read_record(rfid_toolbox_t *tb, const uint8_t *uid, size_t uid_len, rfid_record_v1_t *rec)
{
    esp_err_t err = tb->hal.mifare_auth(tb->hal.ctx, tb->cfg.record_block, tb->cfg.key6, uid, uid_len, tb->cfg.use_key_b);
    if (err != ESP_OK) return RFID_AUTH_FAIL;

    uint8_t block[16];
    err = tb->hal.mifare_read_block(tb->hal.ctx, tb->cfg.record_block, block);
    if (err != ESP_OK) return RFID_READ_FAIL;

    memcpy(rec, block, sizeof(*rec));
    return RFID_OK;
}

static rfid_status_t write_record(rfid_toolbox_t *tb, const uint8_t *uid, size_t uid_len, const rfid_record_v1_t *rec)
{
    esp_err_t err = tb->hal.mifare_auth(tb->hal.ctx, tb->cfg.record_block, tb->cfg.key6, uid, uid_len, tb->cfg.use_key_b);
    if (err != ESP_OK) return RFID_AUTH_FAIL;

    uint8_t block[16];
    memcpy(block, rec, sizeof(*rec));

    err = tb->hal.mifare_write_block(tb->hal.ctx, tb->cfg.record_block, block);
    if (err != ESP_OK) return RFID_WRITE_FAIL;

    return RFID_OK;
}

rfid_status_t rfid_provision_current_tag(rfid_toolbox_t *tb, const uint8_t tag_id_8[8], uint32_t initial_counter)
{
    uint8_t uid[10];
    size_t uid_len = sizeof(uid);
    esp_err_t err = tb->hal.poll_uid(tb->hal.ctx, uid, &uid_len);
    if (err == ESP_ERR_NOT_FOUND) return RFID_NO_CARD;
    if (err != ESP_OK) return RFID_HW_FAIL;

    rfid_record_v1_t rec;
    memset(&rec, 0, sizeof(rec));
    memcpy(rec.tag_id, tag_id_8, 8);
    rec.counter = initial_counter;
    hmac_trunc4(tb->cfg.master_hmac_key, rec.tag_id, rec.counter, rec.mac);

    rfid_status_t st = write_record(tb, uid, uid_len, &rec);
    if (tb->hal.halt) tb->hal.halt(tb->hal.ctx);
    return st;
}

rfid_status_t rfid_authorize_and_update(rfid_toolbox_t *tb, int *authorized)
{
    if (authorized) *authorized = 0;

    uint8_t uid[10];
    size_t uid_len = sizeof(uid);
    esp_err_t err = tb->hal.poll_uid(tb->hal.ctx, uid, &uid_len);
    if (err == ESP_ERR_NOT_FOUND) return RFID_NO_CARD;
    if (err != ESP_OK) return RFID_HW_FAIL;

    rfid_record_v1_t rec;
    rfid_status_t st = read_record(tb, uid, uid_len, &rec);
    if (st != RFID_OK) return st;

    int all0 = 1, allf = 1;
    for (int i = 0; i < 16; i++) {
        uint8_t v = ((uint8_t*)&rec)[i];
        if (v != 0x00) all0 = 0;
        if (v != 0xFF) allf = 0;
    }
    if (all0 || allf) return RFID_NOT_PROVISIONED;

    uint8_t expected[4];
    hmac_trunc4(tb->cfg.master_hmac_key, rec.tag_id, rec.counter, expected);
    if (memcmp(expected, rec.mac, 4) != 0) return RFID_MAC_FAIL;

    rfid_record_v1_t newrec = rec;
    newrec.counter = rec.counter + 1;
    hmac_trunc4(tb->cfg.master_hmac_key, newrec.tag_id, newrec.counter, newrec.mac);

    st = write_record(tb, uid, uid_len, &newrec);
    if (st != RFID_OK) return st;

    if (tb->hal.halt) tb->hal.halt(tb->hal.ctx);
    if (authorized) *authorized = 1;
    return RFID_OK;
}
