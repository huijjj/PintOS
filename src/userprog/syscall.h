#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
typedef int pid_t;

void syscall_init (void);

void verify_address(void *);
void verify_str(const char *);
void get_arg(void *, int *, int);

void syscall_halt(void);
void syscall_exit(int);
bool syscall_create(const char *, unsigned int);
bool syscall_remove(const char *);
pid_t syscall_exec(const char *);
int syscall_wait(pid_t);
int syscall_open(const char *);
int syscall_filesize(int);
int syscall_read(int, void *, unsigned int);
int syscall_write(int, const void *, unsigned int);
void syscall_seek(int, unsigned int);
unsigned syscall_tell(int);
void syscall_close(int);

#endif /* userprog/syscall.h */
