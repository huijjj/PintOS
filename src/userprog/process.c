#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include <list.h>
#include <hash.h>
#include "vm/page.h"

extern struct lock file_lock;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char * cmd_line) 
{
  // printf("process execute...\n");
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, cmd_line, PGSIZE);

  // parse file name from command line
  int len = strlen(cmd_line) + 1;
  char * _file_name = (char *)malloc(len);
  strlcpy(_file_name, cmd_line, len);
  char * sptr;
  _file_name = strtok_r(_file_name, " ", &sptr);

  if(!filesys_open(_file_name)) { // check if file_name is not valid
    return -1;
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (_file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 

  // printf("...process execute\n");
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  // printf("start process...\n");

  char *file_name = file_name_;
  struct intr_frame if_;
  struct thread * cur = thread_current();

  // initialize hash table
  hash_init(&(cur->vm), vm_hash_func, vm_less_func, NULL);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  char * argv[64];
  int argc = 0;

  int len = strlen(file_name) + 1;
  char * _file_name = (char *)malloc(len);
  strlcpy(_file_name, file_name, len);
  char * sptr;
  char * token;

  // fill up argv 
  for( 
    token = strtok_r(_file_name, " ", &sptr);
    token != NULL;
    token = strtok_r(NULL, " ", &sptr)) {
    argv[argc] = token;
    argc += 1;
  }

  palloc_free_page (file_name);

  cur->load_result = load (argv[0], &if_.eip, &if_.esp);

  sema_up(&(cur->load_lock));

  /* If load failed, quit. */
  if (!(cur->load_result)) {
    free(_file_name);
    thread_exit ();
  }

  arg_stk(argv, argc, &if_);
  free(_file_name);

  // printf("...start process\n");

  // hex_dump(if_.esp, if_.esp, PHYS_BASE - if_.esp, true); // for argument passing debugging

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  int exit_status;
  struct thread * t = get_child(child_tid);
  if(t) {
    sema_down(&(t->child_lock));
    exit_status = t->exit_status;
    list_remove(&(t->child_elem));
    sema_up(&(t->zombie_lock));
    return exit_status;
  }

  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  (cur->next_fd)--;
  for(;cur->next_fd > 1; (cur->next_fd)--) {
    file_close(cur->fdt[cur->next_fd]);
  }

  cur->fdt += 2;
  palloc_free_page(cur->fdt);
  file_close(cur->run_file);


  // destory vm entry
  hash_destroy(&(cur->vm), vm_destroy_func);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  // printf("load...\n");

  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire(&file_lock);

  file = filesys_open (file_name);
  if (file == NULL) 
    {
      lock_release(&file_lock);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  t->run_file = file;
  file_deny_write(t->run_file);

  lock_release(&file_lock);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */

  // printf("...load\n");

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  // printf("load segement...\n");

  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  // printf("initial read_bytes %d\n", read_bytes);
  // printf("initial zero_bytes %d\n", zero_bytes);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      // printf("(loop)read_bytes %d\n", read_bytes);
      // printf("(loop)zero_bytes %d\n", zero_bytes);


      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct vm_entry * vme = malloc(sizeof(struct vm_entry)); // allocate new vm frame
      vme->type = VM_BIN; // since file is excutable, set type to ELF
      vme->vaddr = (void *)upage; // set virtual(user) address
      vme->offset = ofs; // set file offset
      vme->writable = writable; // set access authority
      vme->is_loaded = false; // not loaded yet(lazy loading)
      vme->file = file; // set file pointer
      vme->read_bytes = page_read_bytes; // set read byte
      vme->zero_bytes = page_zero_bytes; // set zero byte
      
      hash_insert(&(thread_current()->vm), &(vme->elem)); // insert initialized page to current thread's vm hash table 

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }

  // printf("...load segement\n");


  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  // printf("setup_stack...\n");

  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }

  struct vm_entry * vme = malloc(sizeof(struct vm_entry)); // allocate new vm frame
  vme->type = VM_ANON; // since file is excutable, set type to ELF
  vme->vaddr = (void *)(((uint8_t *)PHYS_BASE) - PGSIZE); // set virtual(user) address
  vme->writable = true; // set access authority
  vme->is_loaded = true;

  hash_insert(&(thread_current()->vm), &(vme->elem)); // insert initialized page to current thread's vm hash table 
  
  // printf("...setup stack\n");

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

// argument passing
void arg_stk(char ** argv, uint32_t argc, struct intr_frame * if_) {
  int i;
  char * arg_ptr[64];
  
  // stacking argument string
  for(i = argc - 1; i > -1; i--) {
    int arg_len = strlen(argv[i]) + 1;
    if_->esp -= arg_len;
    memcpy(if_->esp, argv[i], arg_len);
    arg_ptr[i] = if_->esp;
  }

  // aligning word boundary
  while((unsigned int)if_->esp % 4 != 0) {
    if_->esp--;
    *(uint8_t *)if_->esp = 0;
  }
  
  // stacking argv[]
  if_->esp -= 4;
  memset(if_->esp, 0, sizeof(char *));
  for(i = argc - 1; i > -1; i--) {
    if_->esp -= 4;
    *(uint32_t *)(if_->esp) = (uint32_t)arg_ptr[i];
  }

  // stacking argv and argc
  if_->esp -= 4;
  *(uint32_t *)(if_->esp) = (uint32_t)(if_->esp + 4);
  if_->esp -= 4;
  *(uint32_t *)(if_->esp) = argc;

  // fake return address
  if_->esp -= 4;
  memset(if_->esp, 0, sizeof(char *));
  
  return;
}

int process_add_file(struct file * f) {

  if(!f) {
    return -1;
  }

  struct thread * cur = thread_current();
  int fd = cur->next_fd;
  
  cur->fdt[fd] = f;
  (cur->next_fd)++;
  
  return fd;  
}

struct file * process_get_file(int fd) {
  struct thread * cur = thread_current ();

  if(fd <= 1 || cur->next_fd <= fd) {
    return 0;
  }

  return cur->fdt[fd];
}

void process_close_file(int fd) {
  struct thread * cur = thread_current ();
  
  if(fd <= 1 || cur->next_fd <= fd) {
    return;
  }

  file_close (cur->fdt[fd]);
  cur->fdt[fd] = NULL;
}

bool handle_mm_fault(struct vm_entry * target) {
  // printf("page fault occured! %x, %d\n", target->vaddr, target->type);
  void * kaddr = palloc_get_page(PAL_USER);
  bool success = false;

  if(!kaddr) {
    return success;
  }


  switch (target->type) {
    case VM_BIN:
      success = load_file(kaddr, target);
      break;
    
    case VM_FILE:
      success = load_file(kaddr, target);
      break;

    case VM_ANON:
      break;

    default:
      return success;
  }

  if(success) {
    install_page(target->vaddr, kaddr, target->writable);
    target->is_loaded = true;
  }
  else {
    palloc_free_page(kaddr);
  }

  // printf("done\n");
  return success;
}