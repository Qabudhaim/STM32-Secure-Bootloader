#include "flash_ops.h"
#include "crypto_ops.h"
#include "stm32f4xx_hal.h"
#include <string.h>
#include "main.h"

// Global variables
uint32_t magic_number = 1359749328;
bool flash_area_valid = true;

void erase_flash(uint32_t start_address, uint16_t number_of_words) {
    static FLASH_EraseInitTypeDef EraseInitStruct;
    uint32_t SectorError = 0;

    HAL_FLASH_Unlock();

    uint32_t start_sector = GetSector(start_address);
    uint32_t end_sector_address = start_address + number_of_words * 4;
    uint32_t end_sector = GetSector(end_sector_address);

    EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
    EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    EraseInitStruct.Sector = start_sector;
    EraseInitStruct.NbSectors = (end_sector - start_sector) + 1;

    if (HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) != HAL_OK) {
        return;
    }

    HAL_FLASH_Lock();
}

void write_flash(uint32_t start_address, uint32_t *data, uint16_t number_of_words) {
    HAL_FLASH_Unlock();

    for (uint16_t i = 0; i < number_of_words; i++) {
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, start_address + i * 4, data[i]);
    }

    HAL_FLASH_Lock();
}

void read_flash(uint32_t start_address, uint32_t *data, uint16_t number_of_words) {
    for (uint16_t i = 0; i < number_of_words; i++) {
        data[i] = *(uint32_t*)(start_address + i * 4);
    }
}

uint32_t GetSector(uint32_t Address) {
    if (Address < 0x08004000) {
        return FLASH_SECTOR_0;
    } else if (Address < 0x08008000) {
        return FLASH_SECTOR_1;
    } else if (Address < 0x0800C000) {
        return FLASH_SECTOR_2;
    } else if (Address < 0x08010000) {
        return FLASH_SECTOR_3;
    } else if (Address < 0x08020000) {
        return FLASH_SECTOR_4;
    } else if (Address < 0x08040000) {
        return FLASH_SECTOR_5;
    } else if (Address < 0x08060000) {
        return FLASH_SECTOR_6;
    } else if (Address < 0x08080000) {
        return FLASH_SECTOR_7;
    }
    return 0xFFFFFFFF; // Invalid sector
}

void get_flash_header(Flash_Header_t *flash_area_header) {
    flash_area_header->magic_number = *((uint32_t*)APP_START_ADDRESS);
    memcpy(flash_area_header->signature, (uint32_t*)(APP_START_ADDRESS + 4), 32);
    flash_area_header->length = *((uint32_t*)(APP_START_ADDRESS + 4 + 32));
    flash_area_header->major_version = *((uint16_t*)(APP_START_ADDRESS + 4 + 32 + 4));
    flash_area_header->minor_version = *((uint16_t*)(APP_START_ADDRESS + 4 + 32 + 4 + 2));
    flash_area_header->patch_version = *((uint16_t*)(APP_START_ADDRESS + 4 + 32 + 4 + 2));
}

bool validate_header(void) {
    Flash_Header_t flash_area_header;
    get_flash_header(&flash_area_header);

    if (flash_area_header.magic_number != magic_number) {
        return false;
    }

    return true;
}

void validate_flash_area(void) {
    flash_area_valid = false;

    Flash_Header_t flash_area_header;
    get_flash_header(&flash_area_header);

    if (flash_area_header.length == 0xFFFFFFFF || flash_area_header.magic_number == 0xFFFFFFFF) {
        return;
    }

    if (flash_area_header.magic_number != magic_number) {
        return;
    }

    uint8_t hash[32];
    get_hash((uint8_t*)(APP_START_ADDRESS + 512), hash, flash_area_header.length);

    if (memcmp(hash, flash_area_header.signature, 32) != 0) {
        return;
    }

    flash_area_valid = true;
}

void jump_to_application(void) {
    void (*app_reset_handler)(void);
    uint32_t msp_value = *(volatile uint32_t*)(APP_START_ADDRESS + APP_HEADER_SIZE);
    uint32_t reset_handler_address = *(volatile uint32_t*)(APP_START_ADDRESS + APP_HEADER_SIZE + 4);

    __disable_irq();

    SysTick->CTRL = 0;
    HAL_RCC_DeInit();
    HAL_DeInit();

    for (uint32_t i = 0; i < 8; i++)
    {
        NVIC->ICER[i] = 0xFFFFFFFF;
        NVIC->ICPR[i] = 0xFFFFFFFF;
    }

    __enable_irq();

    __set_MSP(msp_value);
    __set_PSP(msp_value);
    __set_CONTROL(0);
    app_reset_handler = (void*)reset_handler_address;
    app_reset_handler();
} 
