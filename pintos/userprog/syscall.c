#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* 시스템 콜 인자로 전달된 유저 포인터가 가리키고 있는 주소가 유효 한지 확인합니다.
	커널 주소 영역이거나 유저 페이지 테이블에 매핑 되지 않은 주소 라면 종료(exit(-1)) 시킵니다. */
void
check_address (void *addr) {
	if (is_kernel_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == 0) {
		sys_exit (-1);
	}
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax)
	{
		case SYS_HALT:
			sys_halt ();
			break;
		case SYS_EXIT:
			sys_exit (f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = sys_fork (f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = sys_exec (f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = sys_wait (f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = sys_create (f->R.rdi, f ->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = sys_remove (f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = sys_open (f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = sys_filesize (f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = sys_read (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = sys_write (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			sys_seek (f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = sys_tell (f->R.rdi);
			break;
		case SYS_CLOSE:
			sys_close(f->R.rdi);
			break;
		default:
			printf ("system call exiting\n");
			thread_exit ();
			break;
	}
}

void
sys_halt (void) {
	power_off (); 
}

void
sys_exit (int status) {
	printf ("%s: exit(%d)\n", thread_name (), status);
	thread_current ()->exit_status = status;
	thread_exit ();
}

tid_t
sys_fork (const char *thread_name, struct intr_frame *f) {
	check_address (thread_name);
	return process_fork (thread_name, f);
}

int 
sys_exec (const char *cmd_line){
	check_address(cmd_line);
	if (process_exec (cmd_line) < 0)
		sys_exit (-1);
}

int
sys_wait (tid_t pid) {
	return process_wait (pid);
}

bool
sys_create (const char *file, unsigned initial_size) {
	check_address (file);
	return filesys_create (file, initial_size);
}

bool
sys_remove (const char *file) {
	check_address (file);
	return filesys_remove (file);
}

int
sys_open (const char *file) {
	check_address (file);
	return process_file_open (file);
}

int
sys_filesize (int fd) {
	return process_file_length (fd);
}

int
sys_read (int fd, void *buffer, unsigned size) {
	check_address (buffer);
	return process_file_read (fd, buffer, size);
}

int
sys_write (int fd, const void *buffer, unsigned size) {
	check_address (buffer);
	return process_file_write (fd, buffer, size);
}

void
sys_seek (int fd, unsigned position) {
	process_file_seek (fd, position);
}

unsigned
sys_tell (int fd) {
	return process_file_tell (fd);
}

void 
sys_close (int fd){
	process_file_close (fd);
}