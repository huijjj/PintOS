#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  verify_address(f->esp);
  int args[3];

  switch(*(uint32_t *)(f->esp)) {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      get_arg(f->esp, args, 1);
      exit(args[0]);
      break;

    case SYS_EXEC:
      get_arg(f->esp, args, 1);
      exec((const char *)args[0]);
      break;
    
    case SYS_WAIT:
      get_arg(f->esp, args, 1);
      wait((pid_t)args[0]);
      break;
    
    case SYS_CREATE:
      get_arg(f->esp, args, 2);
      create((const char *)args[0], (unsigned int)args[1]);
      break;

    case SYS_REMOVE:
      get_arg(f->esp, args, 1);
      remove((const char *)args[0]);
      break;

    case SYS_OPEN:
      get_arg(f->esp, args, 1);
      open((const char *)args[0]);
      break;

    case SYS_FILESIZE:
      get_arg(f->esp, args, 1);
      filesize((int)args[0]);
      break;

    case SYS_READ:
      get_arg(f->esp, args, 3);
      read((int)args[0], (void *)args[1], (unsigned int)args[2]);
      break;

    case SYS_WRITE:
      get_arg(f->esp, args, 3);
      write((int)args[0], (void *)args[1], (unsigned int)args[2]);
      break;

    case SYS_SEEK:
      get_arg(f->esp, args, 2);
      seek((int)args[0], (unsigned int)args[1]);
      break;

    case SYS_TELL:
      get_arg(f->esp, args, 1);
      tell((int)args[0]);
      break;

    case SYS_CLOSE:
      get_arg(f->esp, args, 1);
      close((int)args[0]);
      break;
  }
  // thread_exit ();
}

void verify_address(void * addr) {
  if(!is_user_vaddr(addr)) {
    exit(-1);
  }

  return;
}

void get_arg(void * esp, int * args, int count) {
  int i;
  int * ptr;
  
  for(i = 0; i < count; i++) {
    ptr = (int *)esp + i + 1;
    verify_address(ptr);
    args[i] = *ptr;
  }

  return;
}

void halt() {
  shutdown_power_off();
}

void exit(int status) {
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status = status;
  thread_exit();
}

bool create(const char * file, unsigned int initial_size) {

}

bool remove(const char * file) {

}

pid_t exec(const char * cmd_lime) {
  return process_execute(cmd_lime);
}

int wait(pid_t pid) {
  return process_wait(pid);
}

int open(const char * file) {

}

int filesize(int fd) {

}

int read(int fd, void * buffer, unsigned size) {
  int i;
  if (fd == STDIN_FILENO) {
    for (i = 0; i < size; i ++) {
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
  }
  return i;
}

int write(int fd, const void * buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }
  
  // else {
  //   lock_acquire(&file_system_lock);
  //   struct file * file_ptr = get_file(fd);
  //   if (!file_ptr) {
  //     lock_release(&file_system_lock);
  //     return ERROR;
  //   }

  //   int written = file_write(file_ptr, buffer, size);
  //   lock_release(&file_system_lock);
  //   return written;
  // }
}

void seek(int fd, unsigned position) {

}

unsigned tell(int fd) {

}

void close(int fd) {

}
