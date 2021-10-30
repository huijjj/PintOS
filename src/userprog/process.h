#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/interrupt.h"
#include <stdlib.h>

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

// argument passing
void arg_stk(char **, uint32_t, struct intr_frame *);
#endif /* userprog/process.h */
