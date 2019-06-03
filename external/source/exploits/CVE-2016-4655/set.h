/*
 * set.h - High-level handler to set boot nonce
 *
 * Copyright (c) 2017 Siguza & tihmstar
 */

#ifndef SET_H
#define SET_H

#include <stdbool.h>

bool set_generator(const char *gen);

bool dump_apticket(const char *to);

#endif
