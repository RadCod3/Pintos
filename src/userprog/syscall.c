#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <stdio.h>
#include <syscall-nr.h>

struct lock f_lock;

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    lock_init(&f_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED) {

    thread_exit();
}

/*function read memory from user virtual address space*/
static int read_memory(void *addr, void *buffer, unsigned size) {
    unsigned i;
    int result = 1;
    for (i = 0; i < size; i++) {
        int byte = get_user(addr + i);
        if (byte == -1) {
            result = 0;
            break;
        }
        *(char *)(buffer + i) = (uint8_t)byte;
    }
    return result;
}

void halt(void) {
    shutdown_power_off();
}

void exit(int status) {
    struct thread *cur = thread_current();
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

pid_t exec(const char *cmd_line) {
    tid_t pid_child = -1;
    int i = 0;
    int length = sizeof(cmd);
    while (i < length) {
        if (get_user(cmd + i) == -1) {
            sys_exit(-1);
        }
        i++;
    }

    pid_child = process_execute(cmd);
    return pid_child;
}

int open(const char *file) {
}

bool create(const char *file, unsigned initial_size) {
    lock_acquire(&f_lock);
    bool result = filesys_create(file, initial_size);
    lock_release(&f_lock);
    return result;
}

bool remove(const char *file) {
    lock_acquire(&f_lock);
    bool result = filesys_remove(file);
    lock_release(&f_lock);
    return result;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user(const uint8_t *uaddr) {
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result)
        : "m"(*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte) {
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a"(error_code), "=m"(*udst)
        : "q"(byte));
    return error_code != -1;
}
