#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <ctype.h>
#include <stdint.h>
#include <list.h>
#include <hash.h>

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

struct vm_entry {
    uint8_t type;
    void * vaddr; // VA
    bool writable;

    bool is_loaded;
    struct file * file;

    struct list_elem mmap_elem;

    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;

    size_t swap_slot;

    struct hash_elem elem;
};

unsigned vm_hash_func(const struct hash_elem * e, void * aux);
bool vm_less_func(const struct hash_elem * a, const struct hash_elem * b, void * aux);

struct vm_entry * find_vme(void * vaddr);

void vm_destroy_func(struct hash_elem * e, void * aux);

bool load_file(void * kaddr, struct vm_entry * target);

#endif