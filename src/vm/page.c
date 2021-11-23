#include "page.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "threads/synch.h"

extern struct lock file_lock;

unsigned vm_hash_func(const struct hash_elem * e, void * aux) {
    struct vm_entry * vme = hash_entry(e, struct vm_entry, elem);
    return hash_int((int)(vme->vaddr)); // get VPN (or VFN)
}

bool vm_less_func(const struct hash_elem * a, const struct hash_elem * b, void * aux) {
    return hash_entry(a, struct vm_entry, elem)->vaddr < hash_entry(b, struct vm_entry, elem)->vaddr;
}

struct vm_entry * find_vme(void * vaddr) {
    // vaddr -> virtual page
    struct vm_entry target;
    target.vaddr = pg_round_down(vaddr);
    struct hash_elem * e = hash_find(&(thread_current()->vm), &(target.elem));
    return e ? hash_entry(e, struct vm_entry, elem) : NULL;
}

void vm_destroy_func(struct hash_elem * e, void * aux) {
    struct vm_entry * target = hash_entry(e, struct vm_entry, elem);
    // uint32_t * pagedir = thread_current()->pagedir;
    // if(target->is_loaded) {
    //     pagedir_clear_page(pagedir, target->vaddr);
    //     palloc_free_page(pagedir_get_page(pagedir, target->vaddr));
    // }
    // free(target);
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

    if(read_bytes != target->read_bytes) {
        return false; // target->read_bytes is always smaller than page size
    }
    memset(kaddr + read_bytes, 0, target->zero_bytes); // zero-ing out empty area
    return true;
}