#ifndef LINUX_IN_MEM_EXE_H
#define LINUX_IN_MEM_EXE_H

#include "precomp.h"

#include <linux/auxvec.h>

void perform_in_mem_exe(char **argv, char **environ, void *buffer, size_t length, unsigned long int base, unsigned long int entry);

typedef struct
{
  int a_type;                   
  union
    {
      long int a_val;           
      void *a_ptr;              
      void (*a_fcn) (void);     
    } a_un;
} Elf32_auxv_t;

extern unsigned char linux_stub[];
extern unsigned int linux_stub_len;

#endif
