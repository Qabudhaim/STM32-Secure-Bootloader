#include "usb_comm.h"
#include "usbd_cdc_if.h"
#include <string.h>

Queue usbQueue;
uint8_t encryptedUsbBuf[64];
uint8_t usbBuf[64];
uint8_t UID[12];

void usb_nack(uint8_t *data, uint8_t len) {
    uint8_t response[64] = {0};
    uint8_t response_len = 0;

    response[0] = NACK;
    response_len = 1;

    if (len > 0 && data != NULL) {
        if (len > sizeof(response) - 1) {
            len = sizeof(response) - 1;
        }
        memcpy(&response[1], data, len);
        response_len += len;
    }

    usb_write(response, response_len);
}

void usb_ack(uint8_t *data, uint8_t len) {
    uint8_t response[64] = {0};
    uint8_t response_len = 0;

    response[0] = ACK;
    response_len = 1;

    if (len > 0 && data != NULL) {
        if (len > sizeof(response) - 1) {
            len = sizeof(response) - 1;
        }
        memcpy(&response[1], data, len);
        response_len += len;
    }

    usb_write(response, response_len);
}

void usb_write(uint8_t *data, uint8_t len) {
    CDC_Transmit_FS(data, len);
}

uint32_t calculate_crc32(uint8_t *data, uint32_t length) {
    uint32_t crc = 0xFFFFFFFF;

    for (uint32_t i = 0; i < length; i++) {
        crc ^= data[i];

        for (int j = 0; j < 8; j++) {
            if (crc & 0x80000000) {
                crc = (crc << 1) ^ 0x04C11DB7;
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

uint32_t get_uint32_t(uint8_t *buf) {
    if (!buf) {
        return 0;
    }
    return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

uint16_t get_uint16_t(uint8_t *buf) {
    if (!buf) {
        return 0;
    }
    return ((uint16_t)buf[0]) | ((uint16_t)buf[1] << 8);
}

void get_uid(uint8_t *uid) {
    uint32_t *uid_address = (uint32_t*)0x1FFF7A10;
    uint32_t uid_word0 = uid_address[0];
    uint32_t uid_word1 = uid_address[1];
    uint32_t uid_word2 = uid_address[2];

    uid[0] = (uid_word0 >> 0) & 0xFF;
    uid[1] = (uid_word0 >> 8) & 0xFF;
    uid[2] = (uid_word0 >> 16) & 0xFF;
    uid[3] = (uid_word0 >> 24) & 0xFF;

    uid[4] = (uid_word1 >> 0) & 0xFF;
    uid[5] = (uid_word1 >> 8) & 0xFF;
    uid[6] = (uid_word1 >> 16) & 0xFF;
    uid[7] = (uid_word1 >> 24) & 0xFF;

    uid[8] = (uid_word2 >> 0) & 0xFF;
    uid[9] = (uid_word2 >> 8) & 0xFF;
    uid[10] = (uid_word2 >> 16) & 0xFF;
    uid[11] = (uid_word2 >> 24) & 0xFF;
}

bool validate_checksum(uint8_t *packet) {
    uint32_t packet_crc = get_uint32_t(&packet[59]);
    uint32_t crc = calculate_crc32(&packet[3], 56);

    if (crc == packet_crc) {
        return true;
    } else {
        return false;
    }

}
