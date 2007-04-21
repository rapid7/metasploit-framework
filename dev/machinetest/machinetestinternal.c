#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>

#include <ruby.h>
#include <signal.h>
#define PAGE_SIZE 0x1000

static VALUE t_test(VALUE self, VALUE str, VALUE all) {
	int len = 1, pid, status, i;
	char *ptr, *start, *stop;

	str = StringValue(str);

	/* test all of the string, instead of just from the beginning */
	if(all == Qtrue)
		len = RSTRING(str)->len;

	while(len-- > 0) {
		switch(fork()) {
		case -1:
			perror("fork");
			rb_raise(rb_eRuntimeError, "fork failed!");
		case 0:
			for(i = 0; i < 20; i++) {
				signal(i, SIG_DFL);
			}

			ptr = RSTRING(str)->ptr + len;

			start = (char *)((unsigned int)ptr & ~(PAGE_SIZE-1));
			stop  = (char *)(((unsigned int)(ptr + (RSTRING(str)->len - len)) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1));

			__asm__ __volatile__(
				"mov %0, %%eax"
				: 
				: "m"((long)ptr)
				: "%eax");

			if ((i = mprotect(start, (int)(stop - start), PROT_EXEC|PROT_WRITE|PROT_READ)) != 0)
				printf("mprotect failed, %d %d\n", i, errno);

			((void (*)(void)) RSTRING(str)->ptr + len)();
			exit(1);
		default:
			wait(&status);
			if(!WIFSIGNALED(status) || WTERMSIG(status) != 5) {
				return INT2NUM(len);
			}
			break;
		}
	}

	return Qnil;
}

void Init_machinetestinternal() {
	VALUE cTest;

	cTest = rb_define_module_under(
	  rb_define_module("MachineTest"),
	  "Internal"
	);
	rb_define_module_function(cTest, "test", t_test, 2);
}
