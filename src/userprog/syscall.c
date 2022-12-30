#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/stdio.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <stdio.h>
#include <syscall-nr.h>

struct lock f_lock;

static void syscall_handler(struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static int read_memory(void *addr, void *buffer, unsigned size);
bool create(const char *file, unsigned initial_size);
static bool put_user(uint8_t *udst, uint8_t byte);
struct file_descriptor *getfdObject(int fd);

void syscall_init(void) {
    lock_init(&f_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED) {

    int syscall_number;

    if (!read_memory(f->esp, &syscall_number, sizeof(syscall_number))) {
        exit(-1);
    }
    // printf("system call number: %d \t", syscall_number);
    //
    switch (syscall_number) {
    case SYS_EXIT: {
        int exit_code;
        if (!read_memory(f->esp + 4, &exit_code, sizeof(exit_code))) {
            exit(-1);
        }
        exit(exit_code);
        break;
    }
    case SYS_HALT: {
        halt();
        break;
    }

    case SYS_WRITE: {
        int fd;
        void *buffer;
        unsigned size;
        if (!read_memory(f->esp + 4, &fd, sizeof(fd))) {
            exit(-1);
        }
        if (!read_memory(f->esp + 8, &buffer, sizeof(buffer))) {
            exit(-1);
        }
        if (!read_memory(f->esp + 12, &size, sizeof(size))) {
            exit(-1);
        }
        f->eax = write(fd, buffer, size);
        break;
    }
    case SYS_OPEN: {
        const char *file;
        if (!read_memory(f->esp + 4, &file, sizeof(file))) {
            exit(-1);
        }
        f->eax = open(file);
        break;
    }
    case SYS_FILESIZE: {
        int fd;
        if (!read_memory(f->esp + 4, &fd, sizeof(fd))) {
            exit(-1);
        }
        f->eax = filesize(fd);
        break;
    }
    case SYS_CREATE: {
        const char *file;
        unsigned int initial_size;
        if (!read_memory(f->esp + 4, &file, sizeof(file))) {
            exit(-1);
        }
        if (!read_memory(f->esp + 8, &initial_size, sizeof(initial_size))) {
            exit(-1);
        }
        f->eax = create(file, initial_size);
        break;
    }
    default: {
        printf("Unimplemented system call!\n");
        // exit(-1);
        break;
    }
    }
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

// Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h).
// This should be seldom used, because you lose some information about possible deadlock situations, etc.
void halt(void) {
    shutdown_power_off();
}

// Terminates the current user program, returning status to the kernel.
// If the process's parent waits for it (see below), this is the status that will be returned.
// Conventionally, a status of 0 indicates success and nonzero values indicate errors.
void exit(int status) {
    struct thread *cur = thread_current();
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

/*
Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid).
Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason.
Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable.
You must use appropriate synchronization to ensure this.
*/
pid_t exec(const char *cmd_line) {
    tid_t pid_child = -1;
    int i = 0;
    int length = sizeof(cmd_line);
    while (i < length) {
        if (get_user(cmd_line + i) == -1) {
            exit(-1);
        }
        i++;
    }

    pid_child = process_execute(cmd_line);
    return pid_child;
}

/*
Functionality:
The child can exit before the parent performs wait
A process can only perform wait for its children
wait() can be called twice for the same process but second call must fail
Nested waits are possible
pintos shouldnt terminate until initial process exits
*/
int wait(pid_t pid) {
    return process_wait(pid);
}
/*
Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output.
The open system call will never return either of these file descriptors, which are valid as system call arguments only as explicitly described below.

Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.

When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor.
Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position*/
int open(const char *file) {
    /* when a file is opened, it is added to the file descriptor list of the current thread
    and the fd count is incremented by 1. This function then returns the fd count or -1 if the
    file could not be opened.
    */
    if (file == NULL) {
        return -1;
    }

    lock_acquire(&f_lock);
    struct file *fileOpened = filesys_open(file);
    struct thread *cur = thread_current();
    lock_release(&f_lock);
    // printf("Came Here");
    // printf("%d", fileOpened);
    if (fileOpened != NULL) {
        cur->fd_count++;
        struct file_descriptor *fd_obj = malloc(sizeof(struct file_descriptor));
        fd_obj->fd = cur->fd_count;
        fd_obj->file = fileOpened;
        list_push_back(&cur->fd_list, &fd_obj->elem);
        return cur->fd_count;
    }
    return -1;
}

bool create(const char *file, unsigned initial_size) {
    if (!file || get_user(file) == -1) {
        exit(-1);
    }

    // printf("file: %d,\ninitial_size: %d\n", initial_size);
    //
    lock_acquire(&f_lock);
    // printf("Before file creation\n");
    bool result = filesys_create(file, initial_size);
    // printf("After file creation\n");
    // if (result == false) {
    //     printf("File creation failed\n");
    // }

    lock_release(&f_lock);
    return result;
}

bool remove(const char *file) {
    lock_acquire(&f_lock);
    bool result = filesys_remove(file);
    lock_release(&f_lock);
    return result;
}

/*Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system.
The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.

Fd 1 writes to the console.
Your code to write to the console should write all of buffer in one call to putbuf(),
at least as long as size is not bigger than a few hundred bytes.
(It is reasonable to break up larger buffers.)
Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts.*/
int write(int fd, const void *buffer, unsigned size) {

    // to check if the addresses are valid and in user space
    if (fd < 0 || get_user(buffer) == -1 || get_user(buffer + size) == -1) {
        exit(-1);
        // return -1;
    }
    // printf("size: %d, buff   er: %s, fd: %d, \t", size, buffer, fd);

    // if fd is 1, then write to console
    if (fd == STDOUT_FILENO) {
        putbuf((const char *)buffer, size);
        return size;
    }

    // acquire lockto access the file system
    lock_acquire(&f_lock);

    // actual_byte_count stores the actual number of bytes written to the file
    // This may differ from the given size because space for a single file is limited and cannot grow.

    struct file_descriptor *fd_obj = getfdObject(fd);

    if (fd_obj == NULL) {
        return -1;
    }
    struct file *fd_file = fd_obj->file;
    int actual_byte_count = (int)file_write(fd_file, buffer, size);

    lock_release(&f_lock);
    return actual_byte_count;
}

int filesize(int fd) {
    lock_acquire(&f_lock);
    int size = file_length(fd);
    lock_release(&f_lock);
    return size;
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

// get the file_descriptor from fd_list in current thread.
struct file_descriptor *getfdObject(int fd) {
    struct list_elem *element;
    struct list *fd_list = &thread_current()->fd_list;
    for (element = list_begin(fd_list); element != list_end(fd_list); element = list_next(element)) {
        struct file_descriptor *fd_obj = list_entry(element, struct file_descriptor, elem);
        if (fd_obj->fd == fd) {
            return fd_obj;
        }
    }
    return NULL;
}
