//
// License:
// https://github.com/rapid7/metasploit-framework/blob/master/LICENSE
//

typedef struct _div_t {
  int quot;
  int rem;
} div_t;

typedef struct _ldiv_t {
  long quot;
  long rem;
} ldiv_t;

typedef struct _lldiv_t {
  long long quot;
  long long rem;
} lldiv_t;

int rand(void);
void srand(unsigned);
void* malloc(size_t);
void* realloc(void*, size_t);
void free(void*);
double atof(const char*);
double strtod(const char*, char**);
float strtof(const char*, char**);
long int strtol(const char*, char**, int);
long double strtold(const char*, char**);
int atoi(const char*);
void abort(void);
void exit(int);
int atexit(void (*function)(void));
char* getenv(const char*);
int setenv(const char*, const char*, int);
int putenv(char*);
int unsetenv(const char*);
void *bsearch(const void*, const void*, size_t, size_t, int (*compar)(const void*, const void*));
void qsort(void*, size_t, size_t, int (*compar)(const void*, const void*));
int abs(int);
int mblen(const char*, size_t);
int system(const char*);
long int labs(long int);
div_t div(int, int);
ldiv_t ldiv(long int, long int);
void* malloc (size_t size);

