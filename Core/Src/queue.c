/*
 * queue.c
 *
 *  Created on: Dec 22, 2024
 *      Author: qusai
 */

#include "queue.h"

// Function to initialize the queue
void init_queue(Queue *q) {
    if (!q) return;

    q->queue_size = QUEUE_SIZE;
    q->num_elements = 0;
    q->current_pointer = 0;
}

// Function to enqueue a buffer into the queue
bool enqueue(Queue *q, const uint8_t *data) {
    if (!q || q->num_elements >= q->queue_size || !data) {
        return false; // Queue is full or invalid input
    }

    // Calculate the position to enqueue
    size_t enqueue_index = (q->current_pointer + q->num_elements) % q->queue_size;

    // Copy data into the queue buffer
    memcpy(q->buffer[enqueue_index], data, BUFFER_SIZE);

    // Update the number of elements
    q->num_elements++;

    return true;
}

// Function to dequeue a buffer from the queue
bool dequeue(Queue *q, uint8_t *output) {
    if (!q || q->num_elements == 0 || !output) {
        return false; // Queue is empty or invalid input
    }

    // Copy the front buffer to the output
    memcpy(output, q->buffer[q->current_pointer], BUFFER_SIZE);

    // Update the front pointer and number of elements
    q->current_pointer = (q->current_pointer + 1) % q->queue_size;
    q->num_elements--;

    return true;
}

// Function to get the number of elements in the queue
size_t get_num_elements(Queue *q) {
    return (q) ? q->num_elements : 0;
}
