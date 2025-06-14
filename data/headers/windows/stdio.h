//
// License:
// https://github.com/rapid7/metasploit-framework/blob/master/LICENSE
//

FILE* popen(const char*, const char*);
int pclose(FILE*);
int fscanf(FILE*, const char*, ...);
int scanf(const char*, ...);
int sscanf(const char*, const char*, ...);
int vfscanf(FILE*, const char*, va_list);
int vsscanf(const char*, const char*, va_list);
int fclose(FILE*);
void clearerr(FILE*);
int feof(FILE*);
int ferror(FILE*);
int fflush(FILE*);
int fgetpos(FILE*, fpos_t*);
FILE *fopen(const char*, const char*);
size_t fread(void*, size_t, size_t, FILE*);
FILE *freopen(const char*, const char*, FILE*);
int fseek(FILE*, long int, int);
int fsetpos(FILE*, const fpos_t*);
long int ftell(FILE*);
size_t fwrite(const void*, size_t, size_t, FILE*);
int remove(const char*);
int rename(const char*, const char*);
void rewind(FILE*);
void setbuf(FILE*, char*);
int setvbuf(FILE*, char*, int, size_t);
FILE *tmpfile(void);
char *tmpnam(char*);
int fprintf(FILE*, const char*, ...);
int printf(const char*, ...);
int sprintf(char*, const char*, ...);
int vfprintf(FILE*, const char*, va_list);
int vsprintf(char*, const char*, va_list);
int vsnprintf(char*, size_t, const char*, va_list);
int vasprintf(char**, const char*, va_list);
int vdprintf(int, const char*, va_list);
