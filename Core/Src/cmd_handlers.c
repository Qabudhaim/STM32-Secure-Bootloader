#include "cmd_handlers.h"
#include "flash_ops.h"
#include "crypto_ops.h"
#include "usb_comm.h"
#include "uart_comm.h"
#include "stm32f4xx_hal.h"

// External variables
extern mbedtls_aes_context aes_packet_ctx;
extern uint8_t aes_packet_iv[16];
extern unsigned char public_key[65];
extern unsigned char peer_public_key[65];
extern bool handshake_done;
extern uint8_t UID[12];

// Global variables
uint16_t packet_index = 0;
bool flashing_in_progress = false;

void handle_command(uint8_t *packet, Interface_Type interface) {
    // Input validation
    if (packet[0] != '>' || packet[63] != '<') {
        if (interface == INTERFACE_USB) {
            usb_nack(NULL, 0);
        } else {
            uart_nack(NULL, 0);
        }
        return;
    }

    if (!validate_checksum(packet)) {
        uint8_t error = ERROR_CHECKSUM_INVALID;
        if (interface == INTERFACE_USB) {
            usb_nack(&error, 1);
        } else {
            uart_nack(&error, 1);
        }
        return;
    }

    uint8_t cmd = packet[1];
    uint8_t len = packet[2];
    uint8_t ack_data[32];

    switch (cmd) {
        case CMD_TOGGLE_LED:
            handle_cmd_toggle_led1();
            if (interface == INTERFACE_USB) {
                usb_ack(NULL, 0);
            } else {
                uart_ack(NULL, 0);
            }
            break;

        case CMD_ERASE_FLASH:
            handle_cmd_erase_flash(packet);
            if (interface == INTERFACE_USB) {
                usb_ack(NULL, 0);
            } else {
                uart_ack(NULL, 0);
            }
            break;

        case CMD_WRITE_FLASH:
            handle_cmd_write_flash(packet);
            packet_index++;

            if (packet_index * 32 == 512) {
                bool header_is_valid = validate_header();
                if (!header_is_valid) {
                    packet_index = 0;
                    flashing_in_progress = false;
                    reset_iv();
                    uint8_t error = ERROR_HEADER_INVALID;
                    if (interface == INTERFACE_USB) {
                        usb_nack(&error, 1);
                    } else {
                        uart_nack(&error, 1);
                    }
                    break;
                }
            }
            if (interface == INTERFACE_USB) {
                usb_ack(NULL, 0);
            } else {
                uart_ack(NULL, 0);
            }
            break;

        case CMD_READ_FLASH:
            memset(ack_data, 0, 32);
            handle_cmd_read_flash(packet, ack_data);
            if (interface == INTERFACE_USB) {
                usb_ack(ack_data, 32);
            } else {
                uart_ack(ack_data, 32);
            }
            break;

        case CMD_JUMP_TO_APP:
            HAL_PWR_EnableBkUpAccess();
            RTC->BKP0R = 0x00000000;
            HAL_PWR_DisableBkUpAccess();
            handle_cmd_jump_to_app();
            break;

        case CMD_FLASHING_DONE:
            handle_cmd_flashing_done();
            if (interface == INTERFACE_USB) {
                usb_ack(NULL, 0);
            } else {
                uart_ack(NULL, 0);
            }
            break;

        case CMD_HANDSHAKE_X:
            handle_cmd_handshake_x(packet);
            memset(ack_data, 0, 32);
            memcpy(ack_data, &public_key[1], 32);
            if (interface == INTERFACE_USB) {
                usb_ack(ack_data, 32);
            } else {
                uart_ack(ack_data, 32);
            }
            break;

        case CMD_HANDSHAKE_Y:
            handle_cmd_handshake_y(packet);
            memset(ack_data, 0, 32);
            memcpy(ack_data, &public_key[33], 32);
            if (interface == INTERFACE_USB) {
                usb_ack(ack_data, 32);
            } else {
                uart_ack(ack_data, 32);
            }
            break;

        case CMD_RESET:
            handle_cmd_reset(packet);
            break;

        case CMD_GET_UID:
            handle_cmd_get_uid();
            if (interface == INTERFACE_USB) {
                usb_ack(UID, 12);
            } else {
                uart_ack(UID, 12);
            }
            break;

        default:
            break;
    }
}

void handle_cmd_toggle_led1(void) {
    HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_3);
    HAL_Delay(50);
    HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_3);
    HAL_Delay(50);
}

void handle_cmd_erase_flash(uint8_t *packet) {
    uint32_t start_address = get_uint32_t(&packet[3]);
    uint32_t number_of_bytes = get_uint32_t(&packet[7]);
    erase_flash(start_address, number_of_bytes / 4);
}

void handle_cmd_write_flash(uint8_t *packet) {
    if (!flashing_in_progress) {
        flashing_in_progress = true;
        packet_index = 0;
    }

    uint8_t data_length = packet[2];
    uint16_t flash_offset = get_uint16_t(&packet[3]);
    uint32_t flash_address = APP_START_ADDRESS + flash_offset;
    uint32_t data[8] = {0};

    decrypt_data(&aes_packet_ctx, aes_packet_iv, &packet[5], 32, (uint8_t*)data);
    write_flash(flash_address, data, data_length / 4);
}

void handle_cmd_read_flash(uint8_t *packet, uint8_t *data) {
    uint32_t read_address = get_uint32_t(&packet[3]);
    read_flash(read_address, (uint32_t*)data, 8);
}

void handle_cmd_flashing_done(void) {
    flashing_in_progress = false;
    packet_index = 0;
    reset_iv();
    free_aes_context(&aes_packet_ctx);
}

void handle_cmd_handshake_x(uint8_t *packet) {
    peer_public_key[0] = 0x04;
    memcpy(&peer_public_key[1], &packet[3], 32);
}

void handle_cmd_handshake_y(uint8_t *packet) {
    peer_public_key[0] = 0x04;
    memcpy(&peer_public_key[33], &packet[3], 32);
    handshake_done = true;
}

void handle_cmd_reset(uint8_t *packet) {
    NVIC_SystemReset();
}

void handle_cmd_get_uid(void) {
    get_uid(UID);
}

void handle_cmd_jump_to_app(void) {
    jump_to_application();
} 

