#ifndef __FLASH_OPS_H
#define __FLASH_OPS_H

#include "main.h"
#include "stdbool.h"

// Global variables
extern uint32_t magic_number;
extern bool flash_area_valid;

#define APP_START_ADDRESS 0x08020000
#define APP_HEADER_SIZE 0x200

typedef struct {
    uint32_t magic_number;
    uint8_t signature[32];
    uint32_t length;
    uint16_t major_version;
    uint16_t minor_version;
    uint16_t patch_version;
} Flash_Header_t;

// Function declarations
void erase_flash(uint32_t start_address, uint16_t number_of_words);
void write_flash(uint32_t start_address, uint32_t *data, uint16_t number_of_words);
void read_flash(uint32_t start_address, uint32_t *data, uint16_t number_of_words);
uint32_t GetSector(uint32_t Address);
void get_flash_header(Flash_Header_t *flash_area_header);
bool validate_header(void);
void validate_flash_area(void);
void jump_to_application(void);

#endif /* __FLASH_OPS_H */ 
