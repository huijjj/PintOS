#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
typedef int pid_t;

void syscall_init (void);

void verify_address(void *);
void get_arg(void *, int *, int);

void halt(void);
void exit(int);
bool create(const char *, unsigned int);
bool remove(const char *);
pid_t exec(const char *);
int wait(pid_t);
int open(const char *);
int filesize(int);
int read(int, void *, unsigned int);
int write(int, const void *, unsigned int);
void seek(int, unsigned int);
unsigned tell(int);
void close(int);

#endif /* userprog/syscall.h */
