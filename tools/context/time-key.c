/*
 * Outputs the value of time(2) with the 16 least significant bits zeroed out.
 * For use in context keyed payload encoding.
 *
 * Author: Dimitris Glynos <dimitris at census-labs.com>
 */

#include <stdlib.h>
#include <stdio.h>
#define __USE_XOPEN
#include <time.h>

char *app = NULL;

void croak_usage(void)
{
	fprintf(stderr, "usage: %s [date & time]\n"
		"\tSupported date & time format: 'YYYY-MM-DD HH:MM:SS'\n"
		"\te.g. %s '2003-11-04 14:23:10'\n",
		app, app);
	exit(1);
}

time_t parse_time(const char *input)
{
	struct tm t;
	char *p;

	p = strptime(input, "%Y-%m-%d %H:%M:%S", &t);

	if ((!p) || (*p != '\0')) {
		fprintf(stderr, "error while processing time spec!\n");
		croak_usage();
	}

	return mktime(&t);
}

int main(int argc, char *argv[])
{
	time_t t;

	app = argv[0];

	if (argc > 2)
		croak_usage();

	if (argc == 2) 
		t = parse_time(argv[1]);
	else 
		t = time(NULL);

	printf("%#.8lx\n", t & 0xffff0000);
	return 0;
}
