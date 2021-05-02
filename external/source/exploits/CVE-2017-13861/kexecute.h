#import <mach/mach.h>
#import <inttypes.h>

uint64_t Kernel_Execute(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);
void init_Kernel_Execute(void);
void term_Kernel_Execute(void);
