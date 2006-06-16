#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#include <ruby.h>
#include <signal.h>

static VALUE t_test(VALUE self, VALUE str, VALUE all) {
	int len = 1, pid, status, i;

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

			__asm__ __volatile__(
				"mov %0, %%eax"
				: 
				: "m"((long)RSTRING(str)->ptr + len)
				: "%eax");

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
