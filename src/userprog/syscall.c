#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include <string.h>
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/synch.h"

#include "vm/page.h"


struct lock file_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf("(syscall handler)start\n");

  verify_address(f->esp);
  verify_address(f->esp + 1);
  verify_address(f->esp + 2);
  verify_address(f->esp + 3);
  int args[3];

  // printf("(syscall handler) interrupt #: %d\n", *(uint32_t *)(f->esp));

  switch(*(uint32_t *)(f->esp)) {
    case SYS_HALT:
      syscall_halt();
      break;

    case SYS_EXIT:
      get_arg(f->esp, args, 1);
      syscall_exit((int)args[0]);
      break;

    case SYS_EXEC:
      get_arg(f->esp, args, 1);
      verify_str((const char *)args[0]);
      f->eax = syscall_exec((const char *)args[0]);
      break;
    
    case SYS_WAIT:
      get_arg(f->esp, args, 1);
      f->eax = syscall_wait((pid_t)args[0]);
      break;
    
    case SYS_CREATE:
      get_arg(f->esp, args, 2);
      verify_str((const char *)args[0]);
      f->eax = syscall_create((const char *)args[0], (unsigned int)args[1]);
      break;

    case SYS_REMOVE:
      get_arg(f->esp, args, 1);
      verify_str((const char *)args[0]);
      f->eax = syscall_remove((const char *)args[0]);
      break;

    case SYS_OPEN:
      get_arg(f->esp, args, 1);
      verify_str((const char *)args[0]);
      f->eax = syscall_open((const char *)args[0]);
      break;

    case SYS_FILESIZE:
      get_arg(f->esp, args, 1);
      f->eax = syscall_filesize((int)args[0]);
      break;

    case SYS_READ:
      get_arg(f->esp, args, 3);
      verify_buf((void *)args[1], (unsigned int)args[2], true);
      f->eax = syscall_read((int)args[0], (void *)args[1], (unsigned int)args[2]);
      break;

    case SYS_WRITE:
      get_arg(f->esp, args, 3);
      verify_buf((void *)args[1], (unsigned int)args[2], false);
      f->eax = syscall_write((int)args[0], (void *)args[1], (unsigned int)args[2]);
      break;

    case SYS_SEEK:
      get_arg(f->esp, args, 2);
      syscall_seek((int)args[0], (unsigned int)args[1]);
      break;

    case SYS_TELL:
      get_arg(f->esp, args, 1);
      f->eax = syscall_tell((int)args[0]);
      break;

    case SYS_CLOSE:
      get_arg(f->esp, args, 1);
      syscall_close((int)args[0]);
      break;

    default:
      syscall_exit(-1);
  }
  
  // printf("(syscall handler) end\n");
  // thread_exit ();
}

struct vm_entry * verify_vaddr(void * vaddr)
{
  struct vm_entry * vme = find_vme(vaddr);
  if (vme == NULL) {
	  syscall_exit(-1);
  }
  
  return vme;
}

void verify_address(void * addr) {
  // printf("(verify address) %x\n", addr);
  if(!is_user_vaddr(addr) || addr < (void *)0x08048000) {
    // printf("this\n");
    syscall_exit(-1);
  }

  // printf("(verify address) naive done\n");
  verify_vaddr(addr);

  return;
}

void verify_str(const char * str) {
  int i = 0;
  while(true) {
    verify_address(str + i);
    if(*(str + i) == '\0') {
      break;
    }
    i++;
  }

  return;
}

void verify_buf(const void * buf, unsigned int size, bool write) {
  verify_address(buf);
  verify_address(buf + size);
  
  unsigned int i = 0;
  for(; i <= size; i++) {
    struct vm_entry * temp = verify_vaddr(buf + i);
    if(write && temp->writable == false) {
      syscall_exit(-1);
    }
  }
}

void get_arg(void * esp, int * args, int count) {
  int i;
  int * ptr;
  
  for(i = 0; i < count; i++) {
    ptr = (int *)esp + i + 1;
    verify_address(ptr);
    verify_address(ptr + 1);
    verify_address(ptr + 2);
    verify_address(ptr + 3);
    args[i] = *ptr;
  }

  return;
}

void syscall_halt() {
  shutdown_power_off();
}

void syscall_exit(int status) {
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status = status;
  thread_exit();
}

bool syscall_create(const char * file, unsigned int initial_size) {
  return filesys_create(file, initial_size);
}

bool syscall_remove(const char * file) {
  return filesys_remove(file);
}

pid_t syscall_exec(const char * cmd_lime) {
  pid_t pid = process_execute(cmd_lime);
  
  if(pid == TID_ERROR) {
    return TID_ERROR;
  }
  
  struct thread * child = get_child(pid);

  sema_down(&(child->load_lock));

  if(child->load_result) {
    return pid;
  }
  else {
    return TID_ERROR;
  }
}

int syscall_wait(pid_t pid) {
  return process_wait(pid);
}

int syscall_open(const char * file) {
  // printf("opening file: %s...\n", file);
  lock_acquire(&file_lock);
  struct file * f = filesys_open(file);
  lock_release(&file_lock);
  // printf("done!, %x\n", f);
  return process_add_file(f);
}

int syscall_filesize(int fd) {
  struct file * f = process_get_file(fd);
  if(f) {
    return file_length(f);
  }
  else {
    return -1;
  }
}

int syscall_read(int fd, void * buffer, unsigned int size) {
  lock_acquire(&file_lock);
  int i;
  if(fd == STDIN_FILENO) {
    for(i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
      if(((char *)buffer)[i] == '\0') {
        break;
      }
    }
    lock_release(&file_lock);
    return i + 1;
  }
  else {
    struct file * f = process_get_file(fd);
    if(f) {
      i = file_read(f, buffer, size);
      lock_release(&file_lock);
      return i;
    }
    else {
      lock_release(&file_lock);
      return -1;
    }
  }
}

int syscall_write(int fd, const void * buffer, unsigned int size) {
  if (fd == STDOUT_FILENO) {
    lock_acquire(&file_lock);
    putbuf(buffer, size);
    lock_release(&file_lock);
    return size;
  } 
  else {
    lock_acquire(&file_lock);
    struct file * f = process_get_file(fd);
    if(f) {
      int written = file_write(f, buffer, size);
      lock_release(&file_lock);
      return written;
    }
    else {
      lock_release(&file_lock);
      return 0;
    } 
  }
}

void syscall_seek(int fd, unsigned int position) {
  struct file * f = process_get_file(fd);
  if(f) {
    file_seek(f, position);
  }
  else {
    return;
  }
}

unsigned syscall_tell(int fd) {
  struct file * f = process_get_file(fd);
  if(f) {
    return file_tell(f);
  }
  else {
    return -1;
  }
}

void syscall_close(int fd) {
  process_close_file(fd);
}
