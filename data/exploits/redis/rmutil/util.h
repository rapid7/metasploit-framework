#ifndef __UTIL_H__
#define __UTIL_H__

#include <redismodule.h>
#include <stdarg.h>

/// make sure the response is not NULL or an error, and if it is sends the error to the client and
/// exit the current function
#define RMUTIL_ASSERT_NOERROR(ctx, r)                                   \
  if (r == NULL) {                                                      \
    return RedisModule_ReplyWithError(ctx, "ERR reply is NULL");        \
  } else if (RedisModule_CallReplyType(r) == REDISMODULE_REPLY_ERROR) { \
    RedisModule_ReplyWithCallReply(ctx, r);                             \
    return REDISMODULE_ERR;                                             \
  }

#define __rmutil_register_cmd(ctx, cmd, f, mode)                                \
  if (RedisModule_CreateCommand(ctx, cmd, f, mode, 1, 1, 1) == REDISMODULE_ERR) \
    return REDISMODULE_ERR;

#define RMUtil_RegisterReadCmd(ctx, cmd, f) __rmutil_register_cmd(ctx, cmd, f, "readonly")

#define RMUtil_RegisterWriteCmd(ctx, cmd, f) __rmutil_register_cmd(ctx, cmd, f, "write")

/* RedisModule utilities. */

/** DEPRECATED: Return the offset of an arg if it exists in the arg list, or 0 if it's not there */
int RMUtil_ArgExists(const char *arg, RedisModuleString **argv, int argc, int offset);

/* Same as argExists but returns -1 if not found. Use this, RMUtil_ArgExists is kept for backwards
compatibility. */
int RMUtil_ArgIndex(const char *arg, RedisModuleString **argv, int argc);

/**
Automatically conver the arg list to corresponding variable pointers according to a given format.
You pass it the command arg list and count, the starting offset, a parsing format, and pointers to
the variables.
The format is a string consisting of the following identifiers:

    c -- pointer to a Null terminated C string pointer.
    s -- pointer to a RedisModuleString
    l -- pointer to Long long integer.
    d -- pointer to a Double
    * -- do not parse this argument at all

Example: If I want to parse args[1], args[2] as a long long and double, I do:
    double d;
    long long l;
    RMUtil_ParseArgs(argv, argc, 1, "ld", &l, &d);
*/
int RMUtil_ParseArgs(RedisModuleString **argv, int argc, int offset, const char *fmt, ...);

/**
Same as RMUtil_ParseArgs, but only parses the arguments after `token`, if it was found.
This is useful for optional stuff like [LIMIT [offset] [limit]]
*/
int RMUtil_ParseArgsAfter(const char *token, RedisModuleString **argv, int argc, const char *fmt,
                          ...);

int rmutil_vparseArgs(RedisModuleString **argv, int argc, int offset, const char *fmt, va_list ap);

#define RMUTIL_VARARGS_BADARG ((size_t)-1)
/**
 * Parse arguments in the form of KEYWORD {len} {arg} .. {arg}_len.
 * If keyword is present, returns the position within `argv` containing the arguments.
 * Returns NULL if the keyword is not found.
 * If a parse error has occurred, `nargs` is set to RMUTIL_VARARGS_BADARG, but
 * the return value is not NULL.
 */
RedisModuleString **RMUtil_ParseVarArgs(RedisModuleString **argv, int argc, int offset,
                                        const char *keyword, size_t *nargs);

/**
 * Default implementation of an AoF rewrite function that simply calls DUMP/RESTORE
 * internally. To use this function, pass it as the .aof_rewrite value in
 * RedisModuleTypeMethods
 */
void RMUtil_DefaultAofRewrite(RedisModuleIO *aof, RedisModuleString *key, void *value);

// A single key/value entry in a redis info map
typedef struct {
  char *key;
  char *val;
} RMUtilInfoEntry;

// Representation of INFO command response, as a list of k/v pairs
typedef struct {
  RMUtilInfoEntry *entries;
  int numEntries;
} RMUtilInfo;

/**
* Get redis INFO result and parse it as RMUtilInfo.
* Returns NULL if something goes wrong.
* The resulting object needs to be freed with RMUtilRedisInfo_Free
*/
RMUtilInfo *RMUtil_GetRedisInfo(RedisModuleCtx *ctx);

/**
* Free an RMUtilInfo object and its entries
*/
void RMUtilRedisInfo_Free(RMUtilInfo *info);

/**
* Get an integer value from an info object. Returns 1 if the value was found and
* is an integer, 0 otherwise. the value is placed in 'val'
*/
int RMUtilInfo_GetInt(RMUtilInfo *info, const char *key, long long *val);

/**
* Get a string value from an info object. The value is placed in str.
* Returns 1 if the key was found, 0 if not
*/
int RMUtilInfo_GetString(RMUtilInfo *info, const char *key, const char **str);

/**
* Get a double value from an info object. Returns 1 if the value was found and is
* a correctly formatted double, 0 otherwise. the value is placed in 'd'
*/
int RMUtilInfo_GetDouble(RMUtilInfo *info, const char *key, double *d);

/*
* Returns a call reply array's element given by a space-delimited path. E.g.,
* the path "1 2 3" will return the 3rd element from the 2 element of the 1st
* element from an array (or NULL if not found)
*/
RedisModuleCallReply *RedisModule_CallReplyArrayElementByPath(RedisModuleCallReply *rep,
                                                              const char *path);

/**
 * Extract the module type from an opened key.
 */
typedef enum {
  RMUTIL_VALUE_OK = 0,
  RMUTIL_VALUE_MISSING,
  RMUTIL_VALUE_EMPTY,
  RMUTIL_VALUE_MISMATCH
} RMUtil_TryGetValueStatus;

/**
 * Tries to extract the module-specific type from the value.
 * @param key an opened key (may be null)
 * @param type the pointer to the type to match to
 * @param[out] out if the value is present, will be set to it.
 * @return a value in the @ref RMUtil_TryGetValueStatus enum.
 */
int RedisModule_TryGetValue(RedisModuleKey *key, const RedisModuleType *type, void **out);

#endif
