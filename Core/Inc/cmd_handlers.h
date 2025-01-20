#ifndef __CMD_HANDLERS_H
#define __CMD_HANDLERS_H

#include "main.h"
#include <string.h>
#include <stdbool.h>

// Global variables
extern uint16_t packet_index;
extern bool flashing_in_progress;

// Command definitions
#define ACK 0x7A
#define NACK 0xA5

#define CMD_TOGGLE_LED 0x20
#define CMD_ERASE_FLASH 0x21
#define CMD_WRITE_FLASH 0x22
#define CMD_READ_FLASH  0x23
#define CMD_JUMP_TO_APP 0x24
#define CMD_FLASHING_DONE 0x25
#define CMD_HANDSHAKE_X 0x26
#define CMD_HANDSHAKE_Y 0x27
#define CMD_RESET 0x28
#define CMD_GET_UID 0x29

// Error codes
#define ERROR_CHECKSUM_INVALID 0xE0
#define ERROR_HEADER_INVALID 0xE1

// Interface type enum
typedef enum {
    INTERFACE_USB,
    INTERFACE_UART
} Interface_Type;

// Function declarations
void handle_command(uint8_t *packet, Interface_Type interface);
void handle_cmd_toggle_led1(void);
void handle_cmd_erase_flash(uint8_t *packet);
void handle_cmd_write_flash(uint8_t *packet);
void handle_cmd_read_flash(uint8_t *packet, uint8_t *data);
void handle_cmd_jump_to_app(void);
void handle_cmd_flashing_done(void);
void handle_cmd_handshake_x(uint8_t *packet);
void handle_cmd_handshake_y(uint8_t *packet);
void handle_cmd_reset(uint8_t *packet);
void handle_cmd_get_uid(void);

#endif /* __CMD_HANDLERS_H */ 
