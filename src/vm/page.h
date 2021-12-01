#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <ctype.h>
#include <stdint.h>
#include <list.h>
#include <hash.h>
#include "threads/palloc.h"

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

struct vm_entry { // virtual page metadata
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

struct mmap_file {
  int mapid;
  struct file * file;
  struct list_elem elem;
  struct list vme_list;
};

struct page { // physical page metadata
  void * kaddr;
  struct vm_entry * vme;
  struct thread * t;
  struct list_elem lru_elem;
};

void add_page_to_lru_list(struct page *);
void del_page_from_lru_list(struct page *);

void lru_init(void);

struct page * alloc_page(enum palloc_flags flags);
void free_page(void * kaddr);
void __free_page(struct page *);
struct list_elem * get_next_lru_clock();

void swap_init(void);
size_t swap_out(void * kaddr);
void swap_in(size_t used_index, void * kaddr);

void * try_to_free(enum palloc_flags flags);

#endif