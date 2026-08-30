#ifndef _LOG_H_
#define _LOG_H_

#include <stdlib.h>

#define do_error_exit(msg) do {perror("[-] " msg); exit(EXIT_FAILURE); } while(0)

#endif /* _LOG_H_ */
