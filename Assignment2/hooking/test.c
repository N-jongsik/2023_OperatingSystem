#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int main()
{
	syscall(336, getpid()); 
	int fd = 0;
	char buf[50];
	fd = open("abc.txt", O_RDWR);
	for (int i = 1; i <= 4; ++i)
	{
		read(fd, buf, 5);
		lseek(fd, 0, SEEK_END);
		write(fd, buf, 5);
		lseek(fd, i*5, SEEK_SET);
	}
	lseek(fd, 0, SEEK_END);
	write(fd, "HELLO", 6);
	close(fd);
	syscall(336,0);
	return 0;

}

