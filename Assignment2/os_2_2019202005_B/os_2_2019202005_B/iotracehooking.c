#include "ftracehooking.h"

#define __NR_open 2
#define __NR_read 0
#define __NR_close 3
#define __NR_write 1
#define __NR_lseek 8

typedef asmlinkage long (*syscall_ptr_t)(const struct pt_regs *);
syscall_ptr_t *syscall_table;

extern int open_count;
extern int read_count;
extern int close_count;
extern int write_count;
extern int lseek_count;

extern size_t read_bytes;
extern size_t write_bytes;
extern char file_name[100];

syscall_ptr_t open_real;
syscall_ptr_t read_real;
syscall_ptr_t close_real;
syscall_ptr_t write_real;
syscall_ptr_t lseek_real;

static asmlinkage long ftrace_open(const struct pt_regs *regs)
{
	copy_from_user(file_name, (char*)regs->di, sizeof(file_name));
	open_count++;
	return open_real(regs);
}

static asmlinkage long ftrace_read(const struct pt_regs *regs)
{
	read_bytes += regs->dx;
	read_count++;
	return read_real(regs);
}

static asmlinkage long ftrace_close(const struct pt_regs *regs)
{
	close_count++;
	return close_real(regs);
}

static asmlinkage long ftrace_write(const struct pt_regs *regs)
{
	write_bytes += regs->dx;
	write_count++;
	return write_real(regs);
}

static asmlinkage long ftrace_lseek(const struct pt_regs *regs)
{
	lseek_count++;
	return lseek_real(regs);
}

void make_rw(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((u64)addr, &level);
	if( pte->pte &~ _PAGE_RW )
	    pte->pte |= _PAGE_RW;
}

void make_ro(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((u64)addr, &level);
	pte->pte = pte->pte &~ _PAGE_RW;
}

asmlinkage int __init hooking_init(void)
{
	syscall_table = (syscall_ptr_t *) kallsyms_lookup_name("sys_call_table");
	make_rw(syscall_table);

	open_real = syscall_table[__NR_open];
	read_real = syscall_table[__NR_read];
	close_real = syscall_table[__NR_close];
	write_real = syscall_table[__NR_write];
	lseek_real = syscall_table[__NR_lseek];	

	syscall_table[__NR_open] = ftrace_open;
	syscall_table[__NR_read] = ftrace_read;
	syscall_table[__NR_close] = ftrace_close;
	syscall_table[__NR_write] = ftrace_write;
	syscall_table[__NR_lseek] = ftrace_lseek;

	return 0;
}

asmlinkage void __exit hooking_exit(void)
{
	syscall_table = (syscall_ptr_t *) kallsyms_lookup_name("sys_call_table");
	syscall_table[__NR_open] = open_real;
	syscall_table[__NR_read] = read_real;
	syscall_table[__NR_close] = close_real;
	syscall_table[__NR_write] = write_real;
	syscall_table[__NR_lseek] = lseek_real;

	make_ro(syscall_table);
}

module_init(hooking_init);
module_exit(hooking_exit);
MODULE_LICENSE("GPL");
