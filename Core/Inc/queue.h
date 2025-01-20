/*
 * queue.h
 *
 *  Created on: Dec 22, 2024
 *      Author: qusai
 */

#ifndef INC_QUEUE_H_
#define INC_QUEUE_H_

#include "main.h"
#include "stdbool.h"
#include "string.h"

#define QUEUE_SIZE 5 // Maximum number of buffers in the queue
#define BUFFER_SIZE 64 // Size of each buffer

typedef struct {
    uint8_t buffer[QUEUE_SIZE][BUFFER_SIZE]; // Static buffers
    size_t queue_size;      // Maximum number of elements in the queue
    size_t num_elements;    // Current number of elements in the queue
    size_t current_pointer; // Pointer to the front element
} Queue;

void init_queue(Queue *q);
bool enqueue(Queue *q, const uint8_t *data);
bool dequeue(Queue *q, uint8_t *output);
size_t get_num_elements(Queue *q);

extern Queue usbQueue;

#endif /* INC_QUEUE_H_ */
