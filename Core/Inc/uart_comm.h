#ifndef __UART_COMM_H
#define __UART_COMM_H

#include "main.h"
#include <stdint.h>
#include "queue.h"
#include "cmd_handlers.h"

// Global variables
extern Queue uartQueue;
extern uint8_t encryptedUartBuf[64];
extern uint8_t uartBuf[64];
extern uint8_t uartRxBuffer[64];

// Function declarations
void uart_init(void);
void uart_nack(uint8_t *data, uint8_t len);
void uart_ack(uint8_t *data, uint8_t len);
void uart_write(uint8_t *data, uint8_t len);
void handle_uart_cmd(uint8_t *packet);

#endif /* __UART_COMM_H */ 