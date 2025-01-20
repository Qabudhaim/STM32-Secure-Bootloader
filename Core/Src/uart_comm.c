#include "uart_comm.h"
#include "cmd_handlers.h"
#include "crypto_ops.h"
#include <string.h>

// External variables
extern UART_HandleTypeDef huart4;
extern mbedtls_aes_context aes_packet_ctx;
extern uint8_t aes_packet_iv[16];

// Global variables
Queue uartQueue;
uint8_t encryptedUartBuf[64];
uint8_t uartBuf[64];
uint8_t uartRxBuffer[64];
uint8_t uartRxIndex = 0;

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
    if (huart->Instance == UART4) {
        // Enqueue the received data
        enqueue(&uartQueue, uartRxBuffer);
        
        // Reset buffer index
        uartRxIndex = 0;
        
        // Start receiving next packet
        HAL_UART_Receive_IT(huart, uartRxBuffer, 64);
    }
}

void uart_init(void) {
    HAL_UART_Receive_IT(&huart4, uartRxBuffer, 64);
}

void uart_nack(uint8_t *data, uint8_t len) {
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

    uart_write(response, response_len);
}

void uart_ack(uint8_t *data, uint8_t len) {
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

    uart_write(response, response_len);
}

void uart_write(uint8_t *data, uint8_t len) {
    uint8_t packet[64] = {0};  // Initialize all bytes to 0
    
    // Copy data to packet, ensuring we don't overflow
    if (len > 0 && data != NULL) {
        memcpy(packet, data, (len > 64) ? 64 : len);
    }
    
    // Always transmit 64 bytes
    HAL_UART_Transmit(&huart4, packet, 64, HAL_MAX_DELAY);
}

void handle_uart_cmd(uint8_t *packet) {
    handle_command(packet, INTERFACE_UART);
} 
