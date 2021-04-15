#ifndef HEAP_H
#define HEAP_H
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <memory.h>
#include <math.h>
#include "custom_unistd.h"

#define ALIGNMENT 8
#define ALIGN(x) (((x) + (ALIGNMENT - 1)) & ~(ALIGNMENT -1))

#define PAGE_SIZE       4096    // Długość strony w bajtach
#define PAGE_FENCE      1       // Liczba stron na jeden płotek
#define PAGES_AVAILABLE 16384   // Liczba stron dostępnych dla sterty
#define PAGES_TOTAL     (PAGES_AVAILABLE + 2 * PAGE_FENCE)

#define USER_FENCE_TYPE uint16_t
#define USER_FENCE_SIZE (sizeof(uint16_t))


struct block_t {
    struct block_t* next;
    struct block_t* prev;

    size_t size;
    size_t user_size;
    bool free; // 1-wolny; 0-zajęty
    uint32_t checksum;
};

struct heap_t {
    struct block_t* head;
    struct block_t* tail;

    uint8_t* heap_start;
    bool is_initialized;

    USER_FENCE_TYPE left_fence;
    USER_FENCE_TYPE right_fence;
};

enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

size_t align_to_page_size(size_t size);
struct block_t* get_block_from_memblock(void* memblock);

uint32_t calculate_checksum(struct block_t* block);
void set_checksum_in_block(struct block_t* block);
int is_checksum_correct(struct block_t* block);

void* extend_heap();

int heap_setup(void);

void heap_clean(void);

void* heap_malloc(size_t size);

void* heap_calloc(size_t number, size_t size);

void* heap_realloc(void* memblock, size_t count);

void  heap_free(void* memblock);

size_t heap_get_largest_used_block_size(void);

int heap_validate(void);
void show_heap_fences();

enum pointer_type_t get_pointer_type(const void* const pointer);

void* heap_malloc_aligned(size_t count);
void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* memblock, size_t size);

void heap_show();



#endif //HEAP_H
