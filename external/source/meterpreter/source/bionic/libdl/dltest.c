/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <dlfcn.h>

extern char *optarg;
extern int optind, opterr, optopt;

static struct option long_options[] = {
    {"library", required_argument, 0, 'l'},
    {"symbol",  required_argument, 0, 's'},
    {"help",    no_argument,       0, 'h'},
    {0, 0, 0, 0},
};

/* This array must parallel long_options[] */
static const char *descriptions[] = {
    "specify a library path to look up symbol",
    "specify symbol to look up",
    "print this help screen",
};

void print_help(const char *name) {
    fprintf(stdout, 
            "invokation:\n"
            "\t%s [-l <libname>] -s <symbol name>\n"
            "\t%s -h\n\n", name, name);
    fprintf(stdout, "options:\n");
    struct option *opt = long_options;
    const char **desc = descriptions;
    while (opt->name) {
        fprintf(stdout, "\t-%c/--%s%s: %s\n",
                opt->val,
                opt->name,
                (opt->has_arg ? " (argument)" : ""),
                *desc);
        opt++;
        desc++;
    }
}

int get_options(int argc, char **argv, char **lib, char **sym) 
{
    int c;

    *lib = 0;
    *sym = 0;

    while (1) {
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long (argc, argv, 
                         "l:s:h",
                         long_options, 
                         &option_index);
        /* Detect the end of the options. */
        if (c == -1) break;

        switch (c) {
		case 'l':
            *lib = strdup(optarg);
			break;
        case 's': 
            *sym = strdup(optarg);
            break;
        case 'h': print_help(argv[0]); exit(EXIT_FAILURE); break;
        case '?':
            /* getopt_long already printed an error message. */
            break;
        default:
            fprintf(stderr, "Unknown option");
            exit(EXIT_FAILURE);
        }
    }

    return optind;
}

int main(int argc, char **argv)
{
    char *libname, *symname, *prog = *argv;

    get_options(argc, argv, &libname, &symname);

    if (symname == NULL) {
        fprintf(stderr, "You must specify a symbol!\n");
        print_help(prog);
        exit(EXIT_FAILURE);
    }

    {
        const char *dlerr;
        void *handle, *symbol;

        printf("opening library [%s]\n", libname);
        dlerr = dlerror();
        handle = libname ? dlopen(libname, RTLD_NOW) : RTLD_DEFAULT;
        dlerr = dlerror();
        if (dlerr != NULL) fprintf(stderr, "dlopen() error: %s\n", dlerr);

        printf("opening symbol [%s]\n", symname);
        symbol = dlsym(handle, symname);
        dlerr = dlerror();
        if (dlerr != NULL) fprintf(stderr, "dlsym() error: %s\n", dlerr);

        printf("closing library [%s]\n", libname);
        dlclose(handle);
        dlerr = dlerror();
        if (dlerr != NULL) fprintf(stderr, "dlclose() error: %s\n", dlerr);
        else printf("successfully opened symbol\n");
    }

    if (libname != NULL) free(libname);
    if (symname != NULL) free(symname);
    return 0;
}
