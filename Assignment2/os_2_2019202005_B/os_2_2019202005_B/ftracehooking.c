#include "ftracehooking.h"

#define __NR_ftrace 336

int open_count = 0;
int read_count = 0;
int close_count = 0;
int write_count = 0;
int lseek_count = 0;

size_t read_bytes = 0;
size_t write_bytes = 0;
char file_name[100] = {0};

typedef asmlinkage int (*syscall_ptr_t)(const struct pt_regs *);
syscall_ptr_t *syscall_table;
syscall_ptr_t real_ftrace;

EXPORT_SYMBOL(open_count);
EXPORT_SYMBOL(read_count);
EXPORT_SYMBOL(close_count);
EXPORT_SYMBOL(write_count);
EXPORT_SYMBOL(lseek_count);

EXPORT_SYMBOL(read_bytes);
EXPORT_SYMBOL(write_bytes);
EXPORT_SYMBOL(file_name);

pid_t my_pid = 0;

static asmlinkage int ftrace(const struct pt_regs *regs)
{
	pid_t pid = regs->di;

	if(pid == 0)
	{
		struct task_struct *curr;
		curr = current;

		printk("[2019202005] %s file[%s] stats [x] read - %d / written - %d\n", curr->comm, file_name, (int)read_bytes, (int)write_bytes);
		printk("open[%d] close[%d] read[%d] write[%d] lseek[%d]\n",open_count,close_count,read_count,write_count,lseek_count);
		printk("OS Assignment 2 ftrace [%d] End\n",my_pid);
	}
	else
	{
		my_pid = pid;
		open_count = 0;
		read_count = 0;
		close_count = 0;
		write_count = 0;
		lseek_count = 0;

		read_bytes = 0;
		write_bytes = 0;
		file_name[0] = '\0';
		printk("OS Assignment 2 ftrace [%d] Start\n",my_pid);
	}
	return 0;
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
	real_ftrace = syscall_table[__NR_ftrace];
	syscall_table[__NR_ftrace] = ftrace;
	return 0;
}

asmlinkage void __exit hooking_exit(void)
{
	syscall_table = (syscall_ptr_t *) kallsyms_lookup_name("sys_call_table");
	make_rw(syscall_table);
	syscall_table[__NR_ftrace] =real_ftrace;
	make_ro(syscall_table);
}

module_init(hooking_init);
module_exit(hooking_exit);
MODULE_LICENSE("GPL");
