#include "heap.h"
#include "tested_declarations.h"
#include "rdebug.h"

struct heap_t pheap = {.is_initialized = false};


void set_fences_in_block(struct block_t *block) {
    *((USER_FENCE_TYPE *) ((uint8_t *) block + sizeof(struct block_t))) = pheap.left_fence;
    *((USER_FENCE_TYPE *) ((uint8_t *) block + sizeof(struct block_t) + USER_FENCE_SIZE + block->user_size)) = pheap.right_fence;
}

USER_FENCE_TYPE *get_user_block_left_fence_pointer(struct block_t *block) {
    return (USER_FENCE_TYPE *) ((uint8_t *) block + sizeof(struct block_t));
}

USER_FENCE_TYPE *get_user_block_right_fence_pointer(struct block_t *block) {
    return (USER_FENCE_TYPE *) ((uint8_t *) block + sizeof(struct block_t) + USER_FENCE_SIZE + block->user_size);
}

USER_FENCE_TYPE get_user_block_left_fence(struct block_t *block) {
    USER_FENCE_TYPE left_fence = *get_user_block_left_fence_pointer(block);
    return left_fence;
}

USER_FENCE_TYPE get_user_block_right_fence(struct block_t *block) {
    USER_FENCE_TYPE right_fence = *get_user_block_right_fence_pointer(block);
    return right_fence;
}

void show_heap_fences() {
    printf("HEAP FENCES: left fence: %d, right fence: %d\n", pheap.left_fence, pheap.right_fence);
}

uint32_t calculate_checksum(struct block_t *block) {
    uint32_t sum = 0;
    uint8_t *start = (uint8_t *) block;
    uint8_t *end = (uint8_t *) (block + 1);

    while (start < end) {
        sum += *start;
        start++;
    }
    return sum;
}

void set_checksum_in_block(struct block_t *block) {
    block->checksum = 0;

    uint32_t sum = calculate_checksum(block);
    block->checksum = sum;
}

void merge_blocks(struct block_t *block1, struct block_t *block2) {
    block1->size = block1->size + sizeof(struct block_t) + block2->size;
    block1->next = block2->next;
    set_checksum_in_block(block1);
}

struct block_t *split_free_block_at_address(struct block_t *block, uint8_t *pointer) {
    if (!block->free) return NULL;

    size_t size_for_old_block = pointer - ((uint8_t *) block + sizeof(struct block_t));
    size_t size_for_new_block = ((uint8_t *) block + sizeof(struct block_t) + block->size) - pointer;
    struct block_t *pnext = block->next;
    struct block_t *new_block = (struct block_t *) pointer;

    new_block->prev = block;
    new_block->next = pnext;
    new_block->size = size_for_new_block;
    new_block->user_size = 0;
    new_block->free = true;
    set_checksum_in_block(new_block);

    block->free = true;
    block->size = size_for_old_block;
    block->user_size = 0;
    block->next = new_block;
    set_checksum_in_block(block);

    pnext->prev = new_block;
    set_checksum_in_block(pnext);

    return new_block;
}

void split_block_after_right_fence(struct block_t *block) {
    struct block_t *new_block = (struct block_t *) (get_user_block_right_fence_pointer(block) + USER_FENCE_SIZE);
    struct block_t *pnext = block->next;

    new_block->next = pnext;
    new_block->prev = block;
    new_block->size = block->size - block->user_size - 2 * USER_FENCE_SIZE - sizeof(struct block_t);
    new_block->user_size = 0;
    new_block->free = true;
    set_checksum_in_block(new_block);

    block->next = new_block;
    block->size = block->user_size + 2 * USER_FENCE_SIZE;
    set_fences_in_block(block);
    set_checksum_in_block(block);


    struct block_t *block_after_new_block = new_block->next;
    block_after_new_block->prev = new_block;
    set_checksum_in_block(pnext);

}

struct block_t *get_block_from_memblock(void *memblock) {
    struct block_t *block = ((struct block_t *) ((uint8_t *) memblock - USER_FENCE_SIZE - sizeof(struct block_t)));
    return block;
}

void *get_memblock_from_block(struct block_t *block) {
    void *memblock = (void *) ((uint8_t *) block + sizeof(struct block_t) + USER_FENCE_SIZE);
    return memblock;
}

size_t align_to_page_size(size_t size) {
    return (((size) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1));
}

struct block_t *get_first_fitting_block(size_t size) {
    struct block_t *current;
    bool is_found = false;
    for (current = pheap.head; current != NULL; current = current->next) {
        if (current->size >= size && current->free == true) {
            is_found = true;
            break;
        }
    }

    return is_found ? current : NULL;
}

int are_fences_correct(struct block_t *block) {
    if (get_user_block_left_fence(block) != pheap.left_fence ||
        get_user_block_right_fence(block) != pheap.right_fence)
        return 0;
    else return 1;
}

int is_checksum_correct(struct block_t *block) {
    uint32_t block_checksum = block->checksum;

    block->checksum = 0;
    uint32_t sum = calculate_checksum(block);
    block->checksum = block_checksum;

    if (block_checksum != sum) return 0;
    else return 1;
}

int check_blocks_integrity() {
    struct block_t *current = pheap.head;
    for (; current != NULL; current = current->next) {
        int res = 0;

        res = is_checksum_correct(current);
        if (res != 1) {
            return 3;
        }

        if (current->free == false && current != pheap.head && current != pheap.tail) {
            res = are_fences_correct(current);
            if (res != 1) {
                return 1;
            }
        }
    }
    return 0;
}

void merge_all_free_neighbour_blocks() {
    struct block_t *current;
    for (current = pheap.head; current != NULL; current = current->next) {
        struct block_t* pnext = current->next;
        if (current->free == true && pnext->free == true) {
            merge_blocks(current, current->next);
        }
    }
}

void *extend_heap(size_t count) {
    size_t size_to_extend = align_to_page_size(count);

    void *res = custom_sbrk(size_to_extend);

    if (res == (void *) -1) {
        return ((void *) -1);
    }

    struct block_t *new_block = pheap.tail;
    struct block_t *old_tail_prev = pheap.tail->prev;
    struct block_t *new_tail = (struct block_t *) ((uint8_t *) pheap.tail + size_to_extend);;

    new_tail->prev = new_block;
    new_tail->next = NULL;
    new_tail->size = 0;
    new_tail->user_size = 0;
    new_tail->free = false;
    set_checksum_in_block(new_tail);

    pheap.tail = new_tail;

    new_block->next = new_tail;
    new_block->prev = old_tail_prev;
    new_block->size = size_to_extend - sizeof(struct block_t); //TODO: czy na pewno - sizeof(struct block_t)?
    new_block->user_size = 0;
    new_block->free = true;
    set_checksum_in_block(new_block);

    if (new_block->prev->free == true) {
        merge_blocks(new_block->prev, new_block);
    }

    return (void *) 0;
}

int heap_setup(void) {
    if (pheap.is_initialized) {
        printf("Heap already initialized");
        return -1;
    }

    void *start_block = custom_sbrk(PAGE_SIZE);
    pheap.heap_start = start_block;

    pheap.left_fence = rand() % (int) (pow(2, 8 * USER_FENCE_SIZE) - 1);
    pheap.right_fence = rand() % (int) (pow(2, 8 * USER_FENCE_SIZE) - 1);

    struct block_t *phead = (struct block_t *) ((uint8_t *) pheap.heap_start); // b. graniczny lewy

    struct block_t *ptail = (struct block_t *) ((uint8_t *) pheap.heap_start + PAGE_SIZE -
                                                sizeof(struct block_t)); // b. graniczny prawy

    struct block_t *pfree = (struct block_t *) ((uint8_t *) phead + sizeof(struct block_t));

    pheap.head = phead;
    pheap.tail = ptail;

    phead->next = pfree;
    phead->prev = NULL;
    phead->size = 0;
    phead->user_size = 0;
    phead->free = false;
    set_checksum_in_block(phead);

    ptail->next = NULL;
    ptail->prev = pfree;
    ptail->size = 0;
    ptail->user_size = 0;
    ptail->free = false;
    set_checksum_in_block(ptail);

    pfree->next = ptail;
    pfree->prev = phead;
    pfree->free = true;
    pfree->size = (uint8_t *) ptail - (uint8_t *) pfree - sizeof(struct block_t);
    pfree->user_size = 0;
    set_checksum_in_block(pfree);

    pheap.is_initialized = true;
    return 0;
}

void heap_clean(void) {
    if (pheap.is_initialized == false) {
        printf("Heap is empty.");
        return;
    }

    custom_sbrk(custom_sbrk_get_reserved_memory() * (-1));

    pheap.head = NULL;
    pheap.tail = NULL;
    pheap.heap_start = NULL;
    pheap.is_initialized = false;
}

void *heap_malloc_at_specified_block(struct block_t *block, size_t size) {
    if (size <= 0 || !pheap.is_initialized || heap_validate() != 0) {
        return NULL;
    }

    if (block->size < size) {
        size_t size_to_allocate = align_to_page_size(size);
        void *res = extend_heap(size_to_allocate);
        if (res == (void *) -1) {
            return NULL;
        }
    }

    size_t full_space_needed_for_user_block = size + sizeof(struct block_t) + 2 * USER_FENCE_SIZE;
    size_t space_needed_for_new_empty_block_with_two_fences = sizeof(struct block_t) + 2 * USER_FENCE_SIZE;

    if (block->size > full_space_needed_for_user_block + space_needed_for_new_empty_block_with_two_fences) {
        struct block_t *rest_space_head = (struct block_t *) ((uint8_t *) block +
                                                              full_space_needed_for_user_block);
        struct block_t *pnext = block->next;

        rest_space_head->free = true;
        rest_space_head->size = block->size - full_space_needed_for_user_block;
        rest_space_head->user_size = 0;
        rest_space_head->next = pnext;
        rest_space_head->prev = block;
        set_checksum_in_block(rest_space_head);

        block->free = false;
        block->size = size + 2 * USER_FENCE_SIZE;
        block->user_size = size;
        block->next = rest_space_head;
        set_fences_in_block(block);
        set_checksum_in_block(block);


        pnext->prev = rest_space_head;
        set_checksum_in_block(pnext);
    } else {
        block->free = false;
        block->user_size = size;
        set_fences_in_block(block);
        set_checksum_in_block(block);
    }

    void *ptr_for_user = get_memblock_from_block(block);

    return ptr_for_user;

}

void *heap_malloc(size_t size) {
    if (size <= 0 || !pheap.is_initialized || heap_validate() != 0) {
        return NULL;
    }

    struct block_t *block_to_use = get_first_fitting_block(size + 2 * USER_FENCE_SIZE);

    if (block_to_use == NULL) {
        size_t size_to_allocate = align_to_page_size(size);
        void *res = extend_heap(size_to_allocate);
        if (res == (void *) -1) {
            return NULL;
        }

        block_to_use = get_first_fitting_block(size + 2 * USER_FENCE_SIZE);

        if (block_to_use == NULL) {
            return NULL; // Brak pamieci
        }
    }

    size_t full_space_needed_for_user_block = size + sizeof(struct block_t) + 2 * USER_FENCE_SIZE;
    size_t space_needed_for_new_empty_block_with_two_fences = sizeof(struct block_t) + 2 * USER_FENCE_SIZE;

    if (block_to_use->size > full_space_needed_for_user_block + space_needed_for_new_empty_block_with_two_fences) {
        struct block_t *rest_space_head = (struct block_t *) ((uint8_t *) block_to_use +
                                                              full_space_needed_for_user_block);
        struct block_t *pnext = block_to_use->next;

        rest_space_head->free = true;
        rest_space_head->size = block_to_use->size - full_space_needed_for_user_block;
        rest_space_head->user_size = 0;
        rest_space_head->next = pnext;
        rest_space_head->prev = block_to_use;
        set_checksum_in_block(rest_space_head);

        block_to_use->free = false;
        block_to_use->size = size + 2 * USER_FENCE_SIZE;
        block_to_use->user_size = size;
        block_to_use->next = rest_space_head;
        set_fences_in_block(block_to_use);
        set_checksum_in_block(block_to_use);


        pnext->prev = rest_space_head;
        set_checksum_in_block(pnext);
    } else {
        block_to_use->free = false;
        block_to_use->user_size = size;
        set_fences_in_block(block_to_use);
        set_checksum_in_block(block_to_use);
    }

    void *ptr_for_user = get_memblock_from_block(block_to_use);

    return ptr_for_user;
}

void *heap_calloc(size_t number, size_t size) {
    size_t count = number * size;

    void *ptr_for_user = heap_malloc(count);

    if (ptr_for_user == NULL) {
        return NULL;
    }

    memset(ptr_for_user, 0, count);

    return ptr_for_user;
}

void *heap_realloc(void *memblock, size_t count) {
    if (heap_validate() != 0) {
        return NULL;
    }

    if (memblock != NULL && count == 0) {
        heap_free(memblock);
        return NULL;
    }

    if (memblock == NULL) {
        void *ptr_for_user = heap_malloc(count);
        if (ptr_for_user == NULL) {
            return NULL;
        } else {
            return ptr_for_user;
        }
    }

    if (get_pointer_type(memblock) != pointer_valid) {
        return NULL;
    }

    struct block_t *block = get_block_from_memblock(memblock);
    size_t space_left_after_right_fence = block->size - block->user_size - 2 * USER_FENCE_SIZE;

    //There are many cases
    //1 ---- count < memblock size -> memblock size is decreased ----
    if (count < block->user_size) {
        block->user_size = count;
        set_fences_in_block(block);
        set_checksum_in_block(block);

        //TODO: Czy powinien łączyć?
        //if space left after right fence is big enough to make new block then split current block
        size_t left_space = block->size - block->user_size - 2 * USER_FENCE_SIZE;
        if (left_space > sizeof(struct block_t) + 2 * USER_FENCE_SIZE) {
            split_block_after_right_fence(block);
        }
    }

        //2 ---- count == memblock size -> nothing happens just returning the same pointer ----
    else if (count == block->user_size) {
        return memblock;
    }

        //3 ---- there is hidden space after right fence  >= needed space - memblock size -> move left fence forward to (needed_size - memblock_size) ----

    else if (space_left_after_right_fence > count - block->user_size) {
        block->user_size = count;
        set_fences_in_block(block);
        set_checksum_in_block(block);
    }

        //4 ---- there is free block after memblock >= needed space - memblock size -> (block1)100B used (block2)300B free -(realloc block1 to 150)-> (block1)150B used (block2)250B free ----
    else if (space_left_after_right_fence < count - block->user_size && block->next->free == true &&
             block->size + sizeof(struct block_t) + block->next->size >= count + 2 * USER_FENCE_SIZE) { //czy w warunku na pewno powinno być + 2 * USER_FENCE_SIZE?

        merge_blocks(block, block->next);
        block->user_size = count;
        set_fences_in_block(block);
        set_checksum_in_block(block);

        size_t left_space = block->size - block->user_size - 2 * USER_FENCE_SIZE;
        if (left_space > sizeof(struct block_t) + 2 * USER_FENCE_SIZE) {
            split_block_after_right_fence(block);

//            struct block_t* new_block = block->next;
//            struct block_t* next_after_new_block = new_block->next;
//            if(next_after_new_block->free == true){
//                merge_blocks(new_block, next_after_new_block);
//            }
        }
    }

        //5 ---- there is no block/space after memblock -> we have to move whole memory(memcpy?) to new bigger block ----
        //&
        //6 ---- if memblock is on heap end and there is no space left for reallocating then use custom_sbrk to get more space from OS ----
    else {
        if (block == pheap.tail->prev->prev && pheap.tail->prev->free == true) {
            size_t last_free_block_size = pheap.tail->prev->size + sizeof(struct block_t);
            void *res = extend_heap(align_to_page_size(count - block->user_size - last_free_block_size));

            if (res == (void *) -1) {
                return NULL;
            }

            merge_blocks(block, block->next);
            block->user_size = count;
            set_fences_in_block(block);
            set_checksum_in_block(block);

            size_t left_space = block->size - block->user_size - 2 * USER_FENCE_SIZE;
            if (left_space > sizeof(struct block_t) + 2 * USER_FENCE_SIZE) {
                split_block_after_right_fence(block);

//                struct block_t* new_block = block->next;
//                struct block_t* next_after_new_block = new_block->next;
//                if(next_after_new_block->free == true){
//                    merge_blocks(new_block, next_after_new_block);
//                }
            }

        } else {
            void *new_ptr = heap_malloc(count);
            if (new_ptr == NULL) {
                return NULL;
            }

            memcpy(new_ptr, memblock, block->user_size);
            heap_free(memblock);
            block = get_block_from_memblock(new_ptr);
        }
    }

    //TODO: function to refactor, temporarily couldn't get through tests
    merge_all_free_neighbour_blocks();

    return get_memblock_from_block(block);
}

void heap_free(void *memblock) {
    if (memblock == NULL || get_pointer_type(memblock) != pointer_valid) {
        return;
    }

    struct block_t *current_block = get_block_from_memblock(memblock);

    struct block_t *prev_block = current_block->prev;
    struct block_t *next_block = current_block->next;

    current_block->free = true;
    current_block->user_size = 0;
    set_checksum_in_block(current_block);

    if (prev_block->free == true && next_block->free == true) {
        merge_blocks(prev_block, current_block);
        merge_blocks(prev_block, next_block);
    } else if (prev_block->free == true) {
        merge_blocks(prev_block, current_block);
    } else if (next_block->free == true) {
        merge_blocks(current_block, next_block);
    } else {
        return;
    }
}

size_t heap_get_largest_used_block_size(void) {
    if (pheap.is_initialized == false || heap_validate() != 0) {
        return 0;
    }
    bool is_any = false;

    struct block_t *current = pheap.head;

    struct block_t null_unused_block = {.size = 0, .user_size = 0, .free = true};

    struct block_t *biggest = &null_unused_block;

    for (; current != NULL; current = current->next) {
        if (current->user_size > biggest->user_size && current->free == false) {
            biggest = current;
            is_any = true;
        }
    }

    if (is_any == false) {
        return 0;
    }

    return biggest->user_size;
}

enum pointer_type_t get_pointer_type(const void *const pointer) {
    if (pointer == NULL) {
        return pointer_null;
    }

    struct block_t *block = pheap.head;

    while (block != NULL) {
        if (block->free == true) {

            if (pointer >= (void *) block && pointer < (void *) ((uint8_t *) block + sizeof(struct block_t))) {
                return pointer_control_block;
            } else if (pointer >= (void *) ((uint8_t *) block + sizeof(struct block_t)) &&
                       pointer < (void *) ((uint8_t *) block + sizeof(struct block_t) + block->size)) {
                return pointer_unallocated;
            }

        } else {
            if (pointer >= (void *) block && pointer < (void *) ((uint8_t *) block + sizeof(struct block_t))) {
                return pointer_control_block;
            } else if (pointer >= (void *) get_user_block_left_fence_pointer(block) &&
                       pointer < (void *) ((uint8_t *) get_user_block_left_fence_pointer(block) + USER_FENCE_SIZE)) {
                return pointer_inside_fences;
            } else if (pointer >= (void *) get_user_block_right_fence_pointer(block) &&
                       pointer < (void *) ((uint8_t *) get_user_block_right_fence_pointer(block) + USER_FENCE_SIZE)) {
                return pointer_inside_fences;
            } else if (pointer == (void *) ((uint8_t *) get_user_block_left_fence_pointer(block) + USER_FENCE_SIZE)) {
                return pointer_valid;
            } else if (pointer > (void *) ((uint8_t *) get_user_block_left_fence_pointer(block) + USER_FENCE_SIZE) &&
                       pointer < (void *) get_user_block_right_fence_pointer(block)) {
                return pointer_inside_data_block;
            } else if (pointer >= (void *) ((uint8_t *) get_user_block_right_fence_pointer(block) + USER_FENCE_SIZE) &&
                       pointer < (void *) block->next) {
                return pointer_unallocated;
            }

        }

        block = block->next;
    }

    return pointer_heap_corrupted;
}

int heap_validate(void) {
    if (custom_sbrk_check_fences_integrity() != 0) {
        return 1;
    }

    if (pheap.is_initialized == false) {
        return 2;
    }

    return check_blocks_integrity();
}

bool is_ptr_sufficient_for_aligned(void *ptr) {
    return ((intptr_t) ptr & (intptr_t) (PAGE_SIZE - sizeof(struct block_t) - USER_FENCE_SIZE - 1)) == 0 ? true : false;
}

void *heap_malloc_aligned(size_t count) {
    if (count == 0 || !pheap.is_initialized || heap_validate() != 0) {
        return NULL;
    }

    uint8_t* pointer;
    struct block_t *block;
    bool is_sufficient;

    for (block = pheap.head; block != NULL; block = block->next) {
        pointer = (void *) block;
        for (size_t i = 0; i < block->size; i++) {
            is_sufficient = is_ptr_sufficient_for_aligned(pointer);
            if (is_sufficient && get_pointer_type(pointer) == pointer_unallocated && block->free) {
                break;
            }
            pointer++;
        }
        if (is_sufficient && get_pointer_type(pointer) == pointer_unallocated && block->free) {
            break;
        }
    }

    if(block == NULL){
        extend_heap(count);
        heap_malloc_aligned(count);
    }

    struct block_t* new_block = split_free_block_at_address(block, pointer);
    void* ptr_for_user = heap_malloc_at_specified_block(new_block, count);


    return ptr_for_user;
}

void *heap_calloc_aligned(size_t number, size_t size) {
    size_t count = number * size;

    void *ptr_for_user = heap_malloc_aligned(count);

    if (ptr_for_user == NULL) {
        return NULL;
    }

    memset(ptr_for_user, 0, count);

    return ptr_for_user;
}

void *heap_realloc_aligned(void *memblock, size_t size) {
    if (memblock == NULL) {
        return NULL;
    }
    size++;
    return NULL;
}

void heap_show() {
    if (pheap.is_initialized == false) {
        printf("Heap is not initialized.\n");
        return;
    }

    struct block_t *block = pheap.head;
    int i = 0;
    printf("-------------------------------------------------------------\n");
    while (block != NULL) {
        USER_FENCE_TYPE left_fence = 0;
        USER_FENCE_TYPE right_fence = 0;
        if (block != pheap.head && block != pheap.tail && block->free == false) {
            left_fence = get_user_block_left_fence(block);
            right_fence = get_user_block_right_fence(block);
        }

        printf("Block_num: %d, checksum: %d, free: %d, size: %d, user size: %d, left fence: %d, right fence: %d\n", i,
               block->checksum,
               block->free, (int) block->size, (int) block->user_size, left_fence, right_fence);
        block = block->next;
        i++;
    }
    printf("-------------------------------------------------------------\n");
}



