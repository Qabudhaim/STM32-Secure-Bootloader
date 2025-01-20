#ifndef __USB_COMM_H
#define __USB_COMM_H

#include "main.h"
#include <stdint.h>
#include "queue.h"
#include "cmd_handlers.h"

// Global variables
extern Queue usbQueue;
extern uint8_t encryptedUsbBuf[64];
extern uint8_t usbBuf[64];
extern uint8_t UID[12];

// Function declarations
void usb_nack(uint8_t *data, uint8_t len);
void usb_ack(uint8_t *data, uint8_t len);
void usb_write(uint8_t *data, uint8_t len);
uint32_t calculate_crc32(uint8_t *data, uint32_t length);
uint32_t get_uint32_t(uint8_t *buf);
uint16_t get_uint16_t(uint8_t *buf);
void get_uid(uint8_t *uid);
bool validate_checksum(uint8_t *packet);

#endif /* __USB_COMM_H */ 
