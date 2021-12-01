#include "page.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include <bitmap.h>
#include "devices/block.h"
#include "userprog/syscall.h"
#include <stddef.h>
#include <stdint.h>

extern struct lock file_lock;
struct lock lru_list_lock;
struct list_elem * lru_clock;
struct list lru_list;

struct lock swap_lock;
struct bitmap * swap_bitmap;
struct block * swap_partition;
size_t swap_slot_count;

unsigned vm_hash_func(const struct hash_elem * e, void * aux) {
    struct vm_entry * vme = hash_entry(e, struct vm_entry, elem);
    return hash_int((int)(vme->vaddr)); // get VPN (or VFN, hash index)
}

bool vm_less_func(const struct hash_elem * a, const struct hash_elem * b, void * aux) {
    return hash_entry(a, struct vm_entry, elem)->vaddr < hash_entry(b, struct vm_entry, elem)->vaddr;
}

struct vm_entry * find_vme(void * vaddr) {
    // vaddr -> virtual page
    struct vm_entry target;
    target.vaddr = pg_round_down(vaddr); // remove page offest
    struct hash_elem * e = hash_find(&(thread_current()->vm), &(target.elem));
    return e ? hash_entry(e, struct vm_entry, elem) : NULL;
}

void vm_destroy_func(struct hash_elem * e, void * aux) {
    struct vm_entry * target = hash_entry(e, struct vm_entry, elem);
    uint32_t * pagedir = thread_current()->pagedir;

    if(target) {
        if(target->is_loaded) {
            free_page(pagedir_get_page(pagedir, target->vaddr));
        }
        free(target);
    }

    return;
}

bool load_file(void * kaddr, struct vm_entry * target) {
    // printf("%x, %x, %d, %d\n", target->file, kaddr, target->read_bytes, target->offset);
    size_t read_bytes;
    if(lock_held_by_current_thread(&file_lock)) {
        file_seek(target->file, target->offset);
        read_bytes = file_read(target->file, kaddr, target->read_bytes);
    }
    else {
        lock_acquire(&file_lock);
        file_seek(target->file, target->offset);
        read_bytes = file_read(target->file, kaddr, target->read_bytes);
        // size_t read_bytes = file_read_at(target->file, kaddr, target->read_bytes, target->offset);
        lock_release(&file_lock);
    }

    // printf("read %d bytes\n", read_bytes);

    if(read_bytes == target->read_bytes) {
        memset(kaddr + read_bytes, 0, target->zero_bytes); // zero-ing out empty area
        return true;
    }
    else {
        return false; // target->read_bytes is always smaller than page size
    }
}

void add_page_to_lru_list(struct page * page) {
    lock_acquire(&lru_list_lock);
    if(list_empty(&lru_list)) {
        lru_clock = &(page->lru_elem);
    }
    list_push_back(&lru_list, &(page->lru_elem)); // insert to lru list
    lock_release(&lru_list_lock);
    return;
}

void del_page_from_lru_list(struct page * page) {
    lock_acquire(&lru_list_lock);
    list_remove(&(page->lru_elem)); // remove from lru list
    lock_release(&lru_list_lock);
}

void lru_init() {
    lock_init(&lru_list_lock);
    list_init(&lru_list);
    lru_clock = NULL;
}

struct page * alloc_page(enum palloc_flags flags) {
    // printf("(alloc_page) start!\n");

    void * kaddr = palloc_get_page(flags);


    if(kaddr == NULL) { // physical memory is full
        while(!kaddr) {
            kaddr = try_to_free(flags);
        }
    }

    // printf("found empty page: %x\n", kaddr);

    struct page * p = malloc(sizeof(struct page));
    p->kaddr = kaddr;
    p->t = thread_current();

    add_page_to_lru_list(p);

    // printf("(alloc_page) done!\n");
    return p;
}

void free_page(void * kaddr) {
    struct list_elem * e;
    struct page * p;
    for(e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)) {
        p = list_entry(e, struct page, lru_elem);
        if(p->kaddr == kaddr) {
            __free_page(p);
            return;
        }
    }
}

void __free_page(struct page * page) {
    pagedir_clear_page(page->t->pagedir, page->vme->vaddr);
    palloc_free_page(page->kaddr);
    del_page_from_lru_list(page);
    free(page);
}

struct list_elem * get_next_lru_clock() { // find victim page to evict
    struct list_elem * e;
    struct page * p;
    bool temp;

    // printf("(get_next_lru_clock)start\n");

    lock_acquire(&lru_list_lock);
    // printf("lock acquired!\n");

    for(e = lru_clock; e != list_end(&lru_list); e = list_next(e)) {
        p = list_entry(e, struct page, lru_elem);
        // printf("found entry\n");
        temp = pagedir_is_accessed(p->t->pagedir, p->vme->vaddr);
        // printf("accessed: %d\n", temp);
        if(temp) {
            pagedir_set_accessed(p->t->pagedir, p->vme->vaddr, false);
        }
        else {
            lock_release(&lru_list_lock);
            return e;
        }
    }

    // printf("first loop done\n");

    if(e == list_end(&lru_list)) {
        // printf("reached the end\n");
        for(e = list_begin(&lru_list); e != lru_clock; e = list_next(e)) {
            p = list_entry(e, struct page, lru_elem);
            if(pagedir_is_accessed(p->t->pagedir, p->vme->vaddr)) {
                pagedir_set_accessed(p->t->pagedir, p->vme->vaddr, false);
            }
            else {
                // printf("(get_next_lru_clock)found victim\n");
                lock_release(&lru_list_lock);
                return e;
            }
        }
        lock_release(&lru_list_lock);                
        // printf("(get_next_lru_clock)found victim\n");
        return e;
    }
    // not reached
    // printf("should not be reached\n");
    lock_release(&lru_list_lock);
    return NULL; 
}

void swap_init(void) {
    swap_partition = block_get_role(BLOCK_SWAP);
    lock_init(&swap_lock);
    swap_slot_count = block_size(swap_partition) / 8; // 8 sector(512B == 2^9B) is 1 slot(page, 4KB == 2^12B)
    swap_bitmap = bitmap_create(swap_slot_count);
}

size_t swap_out(void * kaddr) {
    // printf("swapping out\n");
    lock_acquire(&swap_lock);
    // printf("swap lock acquired!\n");
    size_t dst_slot = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);
    if(dst_slot == BITMAP_ERROR || dst_slot >= swap_slot_count) {
        return SIZE_MAX; // return error
    }

    int write_block;
    int dst_sector = dst_slot * 8; // 1 slot is 8 sector
    void * buf = kaddr;
    lock_acquire(&file_lock);
    // printf("file lock acquired!\n");
    for(write_block = 0; write_block < 8; write_block++) { // write page to chosen slot
        block_write(swap_partition, dst_sector, buf);
        dst_sector++;
        buf += 512;
    }
    lock_release(&file_lock);

    lock_release(&swap_lock);

    // printf("done!\n");
    return dst_slot;
}

void swap_in(size_t used_index, void * kaddr) {
    lock_acquire(&swap_lock);

    int read_block;
    int src_sector = used_index * 8;
    void * buf = kaddr;
    lock_acquire(&file_lock);
    for(read_block = 0; read_block < 8; read_block++) {
        block_read(swap_partition, src_sector, buf);
        src_sector++;
        buf += 512;
    }
    lock_release(&file_lock);
    bitmap_set (swap_bitmap, used_index, 0);

    lock_release(&swap_lock);
}

void * try_to_free(enum palloc_flags flags) {
    struct list_elem * e = get_next_lru_clock();
    struct page * p = list_entry(e, struct page, lru_elem);
    struct vm_entry * vme = p->vme;
    size_t swap_slot;

    switch(vme->type) {        
        case VM_BIN:
            if(pagedir_is_dirty(p->t->pagedir, vme->vaddr)) { // if page is dirty, write back
                swap_slot = swap_out(p->kaddr);
                vme->swap_slot = swap_slot;
                vme->type = VM_ANON;
            }
            break;

        case VM_FILE:
            if(pagedir_is_dirty(p->t->pagedir, vme->vaddr)) { // if page is dirty, write back
                lock_acquire(&file_lock);
                file_write_at(vme->file, p->kaddr, vme->read_bytes, vme->offset);
                lock_release(&file_lock);
            }
            break;
        
        case VM_ANON:
            swap_slot = swap_out(p->kaddr);
            vme->swap_slot = swap_slot;
            break;

        default :
            break;
    }
    lru_clock = list_remove(e);

    __free_page(p);
    vme->is_loaded = false; // next access to this page will cause page fault

    return palloc_get_page(flags);
}
