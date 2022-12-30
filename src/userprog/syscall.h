#include <list.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
typedef int pid_t;

/* Object that stores the file descriptor and the file pointer. We use this to
 * store the file descriptor and the file pointer in a list. */
struct file_descriptor {
    int fd;
    struct file *file;
    struct list_elem elem;
};

#endif /* userprog/syscall.h */
