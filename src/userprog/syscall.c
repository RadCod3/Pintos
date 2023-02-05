#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/stdio.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <syscall-nr.h>

struct lock f_lock;

static void syscall_handler(struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static int read_memory(void *addr, void *buffer, unsigned size);
bool create(const char *file, unsigned initial_size);
unsigned tell(int fd);
static bool put_user(uint8_t *udst, uint8_t byte);
struct file_descriptor *getfdObject(int fd);
struct child_wrapper *getChildData(tid_t tid, struct list *thread_list);

/*Initializes the file system lock and registers the system call handler. */
void syscall_init(void) {
    lock_init(&f_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* The system call handler that calls various system calls based on the
system call number. Every time we read from user virtual address space, we
check if the address is valid. If not, we exit the process.
*/
static void
syscall_handler(struct intr_frame *f UNUSED) {

    int syscall_number;

    if (!read_memory(f->esp, &syscall_number, sizeof(syscall_number))) {
        exit(-1);
    }
    // printf("system call number: %d \n", syscall_number);
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
    case SYS_EXEC: {
        const char *cmd_line;
        if (!read_memory(f->esp + 4, &cmd_line, sizeof(cmd_line))) {
            exit(-1);
        }
        f->eax = exec(cmd_line);
        break;
    }
    case SYS_TELL: {
        int fd;
        if (!read_memory(f->esp + 4, &fd, sizeof(fd))) {
            exit(-1);
        }
        f->eax = tell(fd);
        break;
    }
    case SYS_SEEK: {
        int fd;
        unsigned position;
        if (!read_memory(f->esp + 4, &fd, sizeof(fd))) {
            exit(-1);
        }
        if (!read_memory(f->esp + 8, &position, sizeof(position))) {
            exit(-1);
        }
        seek(fd, position);
        break;
    }
    case SYS_READ: {
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
        f->eax = read(fd, buffer, size);
        break;
    }
    case SYS_CLOSE: {
        int fd;
        if (!read_memory(f->esp + 4, &fd, sizeof(fd))) {
            exit(-1);
        }
        close(fd);
        break;
    }
    case SYS_WAIT: {
        tid_t tid;
        if (!read_memory(f->esp + 4, &tid, sizeof(tid))) {
            exit(-1);
        }
        f->eax = wait(tid);
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
        // printf("Unimplemented system call!\n");
        // exit(-1);
        break;
    }
    }
}

/* Function that that reads memory from user virtual address space if the
address is valid. If not, it returns false. */
static int read_memory(void *addr, void *buffer, unsigned size) {
    unsigned i = 0;
    while (i < size && is_user_vaddr(addr + i)) {
        int byte = get_user(addr + i);
        if (byte == -1) {
            break;
        }
        *(char *)(buffer + i) = (uint8_t)byte;
        i++;
    }
    // If i is not equal to size, it means that we have reached an
    // invalid address, or get_user returned -1.
    return i == size;
}

/* Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h).
 This should be seldom used, because you lose some information about possible deadlock
 situations, etc.
 */
void halt(void) {
    shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel.
If the process's parent waits for it (see below), this is the status that will be returned.
Conventionally, a status of 0 indicates success and nonzero values indicate errors.
*/
void exit(int status) {
    struct thread *cur = thread_current();
    // printf("SYS_EXIT was called\n");
    printf("%s: exit(%d)\n", cur->name, status);

    struct child_wrapper *c = getChildData(cur->tid, &cur->parent->child_list);

    c->exit_status = status;
    // Mark current status of the thread.Thread maybe exiting due to completion or being killed.
    if (status == -1) {
        c->status = THREAD_KILLED;
    } else {
        c->status = THREAD_EXITED;
    }

    thread_exit();
}

/*
Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid).
Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason.
Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable.
You must use appropriate synchronization to ensure this.
*/
pid_t exec(const char *cmd_line) {
    struct thread *parent = thread_current();
    tid_t pid = -1;
    // Run the executable using a new thread
    // printf("came here\n");
    pid = process_execute(cmd_line);

    // Get the child_wrapper of above created child thread
    struct child_wrapper *childWrap = getChildData(pid, &parent->child_list);
    // Make the child thread wait until it loads the executable.
    sema_down(&childWrap->child_thread->sema_exec);

    if (!childWrap->loaded) {
        // Loading failed
        return -1;
    }
    return pid;
}

/*
Functionality:
The child can exit before the parent performs wait
A process can only perform wait for its children
wait() can be called twice for the same process but second call must fail
Nested waits are possible
pintos shouldn't terminate until initial process exits
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
    /* When a file is opened, it is added to the file descriptor list of the current thread
    and the fd count is incremented by 1. This function then returns the fd count or -1 if the
    file could not be opened.
    */
    if (file == NULL) {
        return -1;
    }

    // filesys_open() is not thread safe. So we need to acquire the lock before calling it.
    lock_acquire(&f_lock);
    struct file *fileOpened = filesys_open(file);
    lock_release(&f_lock);

    struct thread *cur = thread_current();
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

/*Creates a new file with an initial_size bytes in size. Returns true if successful, false otherwise */
bool create(const char *file, unsigned initial_size) {
    if (!file || !is_user_vaddr(file) || get_user(file) == -1) {
        exit(-1);
    }

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

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system.
The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.

Fd 1 writes to the console.
Your code to write to the console should write all of buffer in one call to putbuf(),
at least as long as size is not bigger than a few hundred bytes.
(It is reasonable to break up larger buffers.)
Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts.*/
int write(int fd, const void *buffer, unsigned size) {

    // to check if the addresses are valid and in user space
    if (fd < 0 || !is_user_vaddr(buffer) || get_user(buffer) == -1 || !is_user_vaddr(buffer + size) || get_user(buffer + size) == -1) {
        exit(-1);
        // return -1;
    }
    // printf("size: %d, buff   er: %s, fd: %d, \t", size, buffer, fd);

    // if fd is 1, then write to console
    if (fd == STDOUT_FILENO) {
        putbuf((const char *)buffer, size);
        return size;
    }

    // actual_byte_count stores the actual number of bytes written to the file
    // This may differ from the given size because space for a single file is limited and cannot grow.

    struct file_descriptor *fd_obj = getfdObject(fd);

    if (fd_obj == NULL) {
        return -1;
    }

    struct file *fd_file = fd_obj->file;

    // acquire lockto access the file system
    lock_acquire(&f_lock);
    int actual_byte_count = (int)file_write(fd_file, buffer, size);
    lock_release(&f_lock);
    return actual_byte_count;
}

/*Returns the position of the next byte to be read or written in open file fd,
expressed in bytes from the beginning of the file. */
unsigned tell(int fd) {
    struct file_descriptor *fd_obj = getfdObject(fd);
    if (fd_obj == NULL) {
        return -1;
    }
    struct file *fd_file = fd_obj->file;

    lock_acquire(&f_lock);
    unsigned position = file_tell(fd_file);
    lock_release(&f_lock);

    return position;
}

/*Changes the next byte to be read or written in open file fd to position, expressed
in bytes from the beginning of the file.*/
void seek(int fd, unsigned position) {
    struct file_descriptor *fd_obj = getfdObject(fd);
    if (fd_obj == NULL) {
        return;
    }
    struct file *fd_file = fd_obj->file;

    lock_acquire(&f_lock);
    file_seek(fd_file, position);
    lock_release(&f_lock);
}
/*Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). */
int read(int fd, void *buffer, unsigned size) {

    if (fd < 0) {
        exit(-1);
        // return -1;
    }

    if (fd == STDIN_FILENO) {
        unsigned i = 0;
        while (i < size) {
            *(uint8_t *)(buffer + i) = input_getc();
            i++;
        }
        return 0;
    }

    struct file_descriptor *fd_obj = getfdObject(fd);
    // if invalid address or fd is not found
    if (fd_obj == NULL || buffer == NULL || get_user(buffer) == -1 || !is_user_vaddr(buffer + size) || get_user(buffer + size) == -1) {

        exit(-1);
        // return -1;
    }
    struct file *fd_file = fd_obj->file;
    lock_acquire(&f_lock);
    int actual_byte_count = (int)file_read(fd_file, buffer, size);
    lock_release(&f_lock);
    return actual_byte_count;
}

/* Closes file descriptor fd. */
void close(int fd) {
    struct file_descriptor *fd_obj = getfdObject(fd);

    if (fd_obj == NULL) {
        return;
    }

    struct file *fd_file = fd_obj->file;

    lock_acquire(&f_lock);
    file_close(fd_file);
    lock_release(&f_lock);

    // removing the file descriptor object from the open files list
    list_remove(&fd_obj->elem);
    // freeing the memory allocated to the file descriptor object
    free(fd_obj);
}
/* Returns the size, in bytes, of the file open as fd. */
int filesize(int fd) {
    struct file_descriptor *fd_obj = getfdObject(fd);
    lock_acquire(&f_lock);
    int size = file_length(fd_obj->file);
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
// search a given list and find a thread with given tid
struct child_wrapper *getChildData(tid_t tid, struct list *thread_list) {
    struct list_elem *e = list_begin(thread_list);
    while (e != list_end(thread_list)) {
        struct child_wrapper *c = list_entry(e, struct child_wrapper, child_elem);
        if (c->process_id == tid) {
            return c;
        }
        e = list_next(e);
    }

    return NULL;
}
// get the file_descriptor from fd_list in current thread.
struct file_descriptor *getfdObject(int fd) {
    struct list *fd_list = &thread_current()->fd_list;
    struct list_elem *element = list_begin(fd_list);

    while (element != list_end(fd_list)) {
        struct file_descriptor *fd_obj = list_entry(element, struct file_descriptor, elem);
        if (fd_obj->fd == fd) {
            return fd_obj;
        }
        element = list_next(element);
    }

    return NULL;
}
