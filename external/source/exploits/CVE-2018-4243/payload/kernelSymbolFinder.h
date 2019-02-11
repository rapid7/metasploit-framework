//
//  kernelSymbolFinder.h
//  KernelSymbolFinder
//
//  Created by Jake James on 8/21/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#import "lzssdec.hpp"

#import <unistd.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <stdbool.h>

#import <mach-o/loader.h>
#import <mach-o/swap.h>


// dunno if the built-in headers have something like this but I couldn't find any so DIY :)
struct symbol {
    uint32_t table_index;
    uint8_t type;
    uint8_t section_index;
    uint16_t description;
    uint64_t address;
};

uint32_t find_macho_header(void);
uint64_t find_symbol(const char *symbol, bool verbose);
int initWithKernelCache(const char *kernelcache);
